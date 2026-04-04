#!/usr/bin/env python3
"""
Pre-populate Open WebUI with Yashigani agent models.

Run from the backoffice container after agents are registered:
  python3 /app/scripts/init-openwebui-agents.py

Creates a system admin account in Open WebUI and registers all active
agents from the Yashigani agent registry as selectable models.
Users see these as @AgentName in the Open WebUI model picker.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

OWUI_URL = os.getenv("OWUI_URL", "http://open-webui:8080")
SYSTEM_EMAIL = "yashigani-system@yashigani.local"
SYSTEM_NAME = "Yashigani System"
SYSTEM_PASS = os.getenv("OWUI_SYSTEM_PASSWORD", "yashigani-system-auto-2026")


def owui_request(path, data=None, token=None, method="GET"):
    """Make a request to Open WebUI API."""
    url = OWUI_URL + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()[:200]}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def get_token():
    """Get system account JWT via signup or signin."""
    # Try signup
    data, code = owui_request("/api/v1/auths/signup", {
        "email": SYSTEM_EMAIL,
        "name": SYSTEM_NAME,
        "password": SYSTEM_PASS,
        "profile_image_url": "",
    }, method="POST")
    if code in (200, 201) and "token" in data:
        return data["token"]

    # Try signin (password-based)
    data, code = owui_request("/api/v1/auths/signin", {
        "email": SYSTEM_EMAIL,
        "password": SYSTEM_PASS,
    }, method="POST")
    if code == 200 and "token" in data:
        return data["token"]

    return None


def get_agents():
    """Get active agents from Yashigani agent registry via Redis."""
    try:
        import redis
        pwd = open("/run/secrets/redis_password").read().strip()
        r = redis.from_url("redis://:" + pwd + "@redis:6379/3", decode_responses=False)
        from yashigani.agents.registry import AgentRegistry
        reg = AgentRegistry(redis_client=r)
        return [a for a in reg.list_all() if a.get("status") == "active"]
    except Exception as e:
        print("Warning: could not read agent registry:", e, file=sys.stderr)
        return []


def main():
    # Wait for Open WebUI to be ready
    for i in range(30):
        try:
            urllib.request.urlopen(OWUI_URL + "/health", timeout=5)
            break
        except Exception:
            if i == 29:
                print("ERROR: Open WebUI not ready after 30 attempts")
                sys.exit(1)
            time.sleep(2)

    token = get_token()
    if not token:
        print("ERROR: Could not get Open WebUI API token")
        sys.exit(1)
    print("Auth: OK")

    # Get agents from registry
    agents = get_agents()
    if not agents:
        print("No agents in registry — skipping model creation")
        return

    # Create each agent as an Open WebUI model
    for agent in agents:
        name = agent.get("name", "Unknown")
        model_id = "@" + name
        desc = "Yashigani agent: " + name + " @ " + agent.get("upstream_url", "?")

        data, code = owui_request("/api/models/create", {
            "id": model_id,
            "name": name + " Agent",
            "meta": {
                "description": desc,
                "profile_image_url": "",
                "capabilities": {"usage": True},
            },
            "base_model_id": "qwen2.5:3b",
            "params": {},
        }, token=token, method="POST")

        if code in (200, 201):
            print("OK: " + name)
        elif "already exists" in str(data.get("error", "")).lower():
            print("EXISTS: " + name)
        else:
            print("FAIL: " + name + " " + str(code) + " " + str(data.get("error", ""))[:100])

    print("Agent model setup complete")


if __name__ == "__main__":
    main()
