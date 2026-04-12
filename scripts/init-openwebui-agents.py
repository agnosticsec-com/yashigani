#!/usr/bin/env python3
"""
Pre-populate Open WebUI with Yashigani agent models.

Run inside the open-webui container:
  podman exec open-webui python3 /tmp/init-openwebui-agents.py

Inserts agent models directly into Open WebUI's SQLite DB.
Idempotent — skips agents that already exist.
"""
import json
import os
import sqlite3
import time

DB_PATH = os.getenv("OWUI_DB_PATH", "/app/backend/data/webui.db")

# Admin user ID — first user created in Open WebUI (auto-provisioned via trusted header)
ADMIN_USER_ID = os.getenv("OWUI_ADMIN_USER_ID", "")

AGENTS = [
    {
        "id": "@LangGraph",
        "name": "LangGraph Agent",
        "base_model_id": "qwen2.5:3b",
        "description": "AI agent framework by LangChain. Multi-step reasoning, tool use, and memory.",
    },
    {
        "id": "@OpenClaw",
        "name": "OpenClaw Agent",
        "base_model_id": "qwen2.5:3b",
        "description": "Open-source AI agent with web search, code execution, and file management.",
    },
]


def main():
    db = sqlite3.connect(DB_PATH)

    # Find the admin user ID if not provided
    admin_id = ADMIN_USER_ID
    if not admin_id:
        row = db.execute(
            "SELECT id FROM user WHERE role = 'admin' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if row:
            admin_id = row[0]
        else:
            # No admin yet — use a placeholder (will be adopted by first admin login)
            admin_id = "00000000-0000-0000-0000-000000000000"

    now = int(time.time())

    for agent in AGENTS:
        # Check if exists
        existing = db.execute(
            "SELECT id FROM model WHERE id = ?", (agent["id"],)
        ).fetchone()
        if existing:
            print("EXISTS: " + agent["name"])
            continue

        meta = json.dumps({
            "description": agent["description"],
            "profile_image_url": "",
            "capabilities": {"usage": True},
        })

        db.execute(
            "INSERT INTO model (id, user_id, base_model_id, name, meta, params, created_at, updated_at, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (agent["id"], admin_id, agent["base_model_id"], agent["name"],
             meta, "{}", now, now, True),
        )
        print("OK: " + agent["name"])

    db.commit()
    db.close()
    print("Done")


if __name__ == "__main__":
    main()
