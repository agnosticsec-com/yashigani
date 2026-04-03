#!/usr/bin/env python3
"""
Ava's QA Test Suite — Playwright browser tests for Yashigani UI.

Tests every user-facing page and API endpoint using headless Chromium.
Run: python3 scripts/test-ui.py [--vm-ip 192.168.64.2] [--domain yashigani.local]

Prerequisites:
  pip install playwright && playwright install chromium
  SSH key at ~/.ssh/yashigani_vm for VM access
  /etc/hosts entry for the domain pointing to VM IP
"""
import asyncio
import argparse
import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

PASS = 0
FAIL = 0
RESULTS = []


def result(name, passed, detail=""):
    global PASS, FAIL
    if passed:
        PASS += 1
        RESULTS.append(f"  {name}: PASS")
    else:
        FAIL += 1
        RESULTS.append(f"  {name}: FAIL — {detail}")
    print(RESULTS[-1])


def get_secret(vm_ip, filename):
    r = subprocess.run(
        ["ssh", "-i", str(Path.home() / ".ssh/yashigani_vm"),
         "-o", "StrictHostKeyChecking=no",
         f"max@{vm_ip}", f"cat ~/yashigani-test/docker/secrets/{filename}"],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip()


def compute_totp(secret_b32):
    secret_b32 += "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32, casefold=True)
    counter = struct.pack(">Q", int(time.time()) // 30)
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


async def run_tests(domain, vm_ip):
    from playwright.async_api import async_playwright

    # Get credentials
    username = get_secret(vm_ip, "admin1_username")
    password = get_secret(vm_ip, "admin_initial_password")
    totp_secret = get_secret(vm_ip, "admin1_totp_secret")

    print(f"\n=== Ava QA Report ===")
    print(f"Target: https://{domain}")
    print(f"Admin: {username}")
    print()

    js_errors = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        page.on("pageerror", lambda exc: js_errors.append(str(exc)))

        base = f"https://{domain}"

        # --- 1. Gateway Health ---
        print("--- Gateway ---")
        try:
            resp = await page.goto(f"{base}/healthz")
            body = await resp.json() if resp else {}
            result("Gateway healthz", body.get("status") == "ok", str(body)[:80])
        except Exception as e:
            result("Gateway healthz", False, str(e)[:80])

        # --- 2. Open WebUI ---
        print("--- Open WebUI ---")
        try:
            resp = await page.goto(base)
            result("Open WebUI loads", resp.status == 200, f"HTTP {resp.status}")
        except Exception as e:
            result("Open WebUI loads", False, str(e)[:80])

        # --- 3. Admin Login Page ---
        print("--- Admin Login ---")
        await page.goto(f"{base}/admin/login")
        await page.wait_for_load_state("networkidle")

        login_form = await page.query_selector("#login-form")
        result("Login page loads", login_form is not None, "form not found" if not login_form else "")

        btn = await page.query_selector("#login-btn")
        btn_text = await btn.text_content() if btn else ""
        result("Login button visible", btn_text == "Sign In", f"got: {btn_text}")

        # --- 4. Login with wrong creds ---
        await page.fill("#username", "wrong")
        await page.fill("#password", "wrong")
        await page.fill("#totp_code", "000000")
        await page.click("#login-btn")
        await page.wait_for_timeout(2000)
        msg = await page.text_content("#msg-box") if await page.query_selector("#msg-box") else ""
        result("Wrong creds shows error", "invalid" in msg.lower() or "failed" in msg.lower(), f"msg: {msg[:60]}")

        # --- 5. Login with correct creds ---
        totp = compute_totp(totp_secret)
        await page.fill("#username", username)
        await page.fill("#password", password)
        await page.fill("#totp_code", totp)
        await page.click("#login-btn")
        await page.wait_for_timeout(2000)

        pw_form = await page.query_selector("#pw-form")
        pw_visible = await pw_form.is_visible() if pw_form else False
        result("Login succeeds (pw change shown)", pw_visible, "password change form not visible")

        # --- 6. Password Change ---
        new_pw = "AvaTestPassword36CharactersMinimumRequired!!"
        if pw_visible:
            await page.fill("#new_password", new_pw)
            await page.fill("#confirm_password", new_pw)
            await page.click("#pw-btn")
            await page.wait_for_timeout(2000)

            login_back = await page.is_visible("#login-form")
            msg2 = await page.text_content("#msg-box") if await page.query_selector("#msg-box") else ""
            result("Password change works", login_back and "changed" in msg2.lower(), f"login_form={login_back}, msg={msg2[:60]}")
        else:
            result("Password change works", False, "skipped — pw form not visible")

        # --- 7. Re-login with new password ---
        print("  Waiting 35s for new TOTP window...")
        await page.wait_for_timeout(35000)

        totp2 = compute_totp(totp_secret)
        await page.fill("#username", username)
        await page.fill("#password", new_pw)
        await page.fill("#totp_code", totp2)
        await page.click("#login-btn")

        try:
            await page.wait_for_url(f"**/admin/", timeout=10000)
            result("Re-login redirects to dashboard", True)
        except:
            result("Re-login redirects to dashboard", False, f"stuck at {page.url}")

        await page.wait_for_timeout(3000)

        # --- 8. Dashboard ---
        print("--- Dashboard ---")
        nav = await page.query_selector(".nav-links")
        result("Navigation visible", nav is not None)

        health = await page.text_content("#health-cards") if await page.query_selector("#health-cards") else ""
        result("Health data loaded", len(health) > 20 and "Loading" not in health, f"content: {health[:60]}")

        stat_acc = await page.text_content("#stat-accounts") if await page.query_selector("#stat-accounts") else "-"
        result("Account count loaded", stat_acc.isdigit(), f"got: {stat_acc}")

        stat_agents = await page.text_content("#stat-agents") if await page.query_selector("#stat-agents") else "-"
        result("Agent count loaded", stat_agents.isdigit(), f"got: {stat_agents}")

        # --- 9. Agents Page ---
        print("--- Pages ---")
        agents_btn = await page.query_selector("button:has-text('Agents')")
        if agents_btn:
            await agents_btn.click()
            await page.wait_for_timeout(2000)
            agents_page = await page.is_visible("#page-agents")
            result("Agents page loads", agents_page)
        else:
            result("Agents page loads", False, "button not found")

        # --- 10. Accounts Page ---
        acc_btn = await page.query_selector("button:has-text('Accounts')")
        if acc_btn:
            await acc_btn.click()
            await page.wait_for_timeout(2000)
            acc_content = await page.text_content("#accounts-tbody") if await page.query_selector("#accounts-tbody") else ""
            result("Accounts page shows data", username in acc_content, f"content: {acc_content[:60]}")
        else:
            result("Accounts page shows data", False, "button not found")

        # --- 11. Alerts Page ---
        alerts_btn = await page.query_selector("button:has-text('Alerts')")
        if alerts_btn:
            await alerts_btn.click()
            await page.wait_for_timeout(1000)
            alerts_visible = await page.is_visible("#page-alerts")
            result("Alerts page loads", alerts_visible)
        else:
            result("Alerts page loads", False, "button not found")

        # --- 12. Logout ---
        logout_btn = await page.query_selector("button:has-text('Logout')")
        if logout_btn:
            await logout_btn.click()
            await page.wait_for_timeout(2000)
            result("Logout redirects to login", "/admin/login" in page.url, f"url: {page.url}")
        else:
            result("Logout redirects to login", False, "button not found")

        # --- 13. JS Errors ---
        result("No JavaScript errors", len(js_errors) == 0, f"{len(js_errors)} errors: {js_errors[:2]}")

        # --- 14. Chat via gateway ---
        print("--- Chat ---")
        try:
            chat_result = subprocess.run(
                ["ssh", "-i", str(Path.home() / ".ssh/yashigani_vm"),
                 "-o", "StrictHostKeyChecking=no", f"max@{vm_ip}",
                 "podman exec docker_open-webui_1 curl -s http://gateway:8080/v1/chat/completions "
                 "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer yashigani-internal' "
                 "-d '{\"model\":\"qwen2.5:3b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}' --max-time 30"],
                capture_output=True, text=True, timeout=45,
            )
            chat_data = json.loads(chat_result.stdout)
            has_choices = "choices" in chat_data
            result("Chat via gateway", has_choices,
                   chat_data["choices"][0]["message"]["content"][:40] if has_choices else str(chat_data)[:80])
        except Exception as e:
            result("Chat via gateway", False, str(e)[:80])

        # Screenshot
        await page.screenshot(path="/tmp/ava_qa_report.png")
        await browser.close()

    # --- Summary ---
    print()
    print("=" * 40)
    for r in RESULTS:
        print(r)
    print("=" * 40)
    print(f"  RESULT: {PASS}/{PASS + FAIL} PASSED")
    if FAIL == 0:
        print("  All clear. Ship it.")
    else:
        print(f"  {FAIL} FAILURE(S) — DO NOT COMMIT")
    print()
    return FAIL == 0


def main():
    parser = argparse.ArgumentParser(description="Ava QA — Playwright UI tests")
    parser.add_argument("--vm-ip", default="192.168.64.2")
    parser.add_argument("--domain", default="yashigani.local")
    args = parser.parse_args()

    ok = asyncio.run(run_tests(args.domain, args.vm_ip))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
