#!/usr/bin/env python3
"""
Bootstrap Postgres for Yashigani.

Generates a 36-char password for the yashigani_app role,
writes it to the secrets volume, runs Alembic migrations.

Prints credentials clearly delimited to stdout exactly once.
Must be run as a one-shot init container before the application starts.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import textwrap
from pathlib import Path


SECRETS_DIR = Path(os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"))
SENTINEL = SECRETS_DIR / ".postgres_bootstrapped"
DB_DSN_ENV = "YASHIGANI_DB_DSN"


def _generate_password() -> str:
    return secrets.token_urlsafe(27)  # 36 chars base64url


def _print_credentials(pg_password: str) -> None:
    block = textwrap.dedent(f"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║            YASHIGANI POSTGRES FIRST-RUN CREDENTIALS                 ║
    ║   Store these securely — they will NOT be shown again.              ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  Postgres password (yashigani_app): {pg_password:<34} ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """).strip()
    print(block, flush=True)


def main() -> None:
    if SENTINEL.exists():
        print("[bootstrap_postgres] Already bootstrapped — skipping.", flush=True)
        return

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate password
    pg_password = _generate_password()

    # Write to secrets file
    pg_password_file = SECRETS_DIR / "postgres_password"
    pg_password_file.write_text(pg_password)
    pg_password_file.chmod(0o600)

    # Ensure license_key secret file exists (empty = Community edition).
    # Docker Compose requires the file to exist even if unused.
    license_key_file = SECRETS_DIR / "license_key"
    if not license_key_file.exists():
        license_key_file.touch()
        license_key_file.chmod(0o600)

    # Build DSN for migration
    pg_host = os.getenv("POSTGRES_HOST", "postgres")
    pg_port = os.getenv("POSTGRES_PORT", "5432")
    pg_db = os.getenv("POSTGRES_DB", "yashigani")
    # Use superuser for initial setup, then app role for runtime
    pg_superuser = os.getenv("POSTGRES_SUPERUSER", "postgres")
    pg_superuser_pw = os.getenv("POSTGRES_SUPERUSER_PASSWORD", "")
    migration_dsn = (
        f"postgresql://{pg_superuser}:{pg_superuser_pw}@{pg_host}:{pg_port}/{pg_db}"
    )

    # Run Alembic migrations
    env = os.environ.copy()
    env[DB_DSN_ENV] = migration_dsn
    result = subprocess.run(
        ["python", "-m", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("[bootstrap_postgres] Alembic migration FAILED:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    print("[bootstrap_postgres] Migrations applied successfully.", flush=True)

    # Update the yashigani_app role password via psql
    update_pw_sql = (
        f"ALTER ROLE yashigani_app WITH PASSWORD '{pg_password}';"
    )
    result2 = subprocess.run(
        ["psql", migration_dsn, "-c", update_pw_sql],
        capture_output=True,
        text=True,
    )
    if result2.returncode != 0:
        print("[bootstrap_postgres] Password update FAILED:", file=sys.stderr)
        print(result2.stderr, file=sys.stderr)
        sys.exit(1)

    # Print credentials
    _print_credentials(pg_password)

    # Mark bootstrapped
    SENTINEL.touch()
    print("[bootstrap_postgres] Bootstrap complete.", flush=True)


if __name__ == "__main__":
    main()
