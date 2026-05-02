#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.23.1 — enable TLS + client-cert verification on Postgres.
#
# This init script runs ONCE on first initdb of the postgres container (the
# stock postgres entrypoint executes /docker-entrypoint-initdb.d/*.sh in
# alphabetical order before starting the server for real).
#
# After this script:
#   * ssl = on in postgresql.conf
#   * Server presents its own leaf cert (./secrets/postgres_client.crt) to
#     connecting clients
#   * Clients must present a cert signed by our internal CA
#     (clientcert=verify-ca)
#   * Password auth (scram-sha-256) still required on top of the cert
#     (defence in depth — three factors: TLS + cert + password)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[05-enable-ssl] Installing server cert chain and enabling TLS"

# Postgres requires SSL material inside PGDATA and owned by the postgres user.
install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${PGDATA}/server.key"
install -m 0644 -o postgres -g postgres /run/secrets/ca_root.crt         "${PGDATA}/root.crt"

# Append TLS settings to postgresql.conf (keep existing settings; our lines
# win by virtue of being later in the file).
cat >> "${PGDATA}/postgresql.conf" <<'PGCONF'

# ── Yashigani internal mTLS ─────────────────────────────────────────────────
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file  = 'server.key'
ssl_ca_file   = 'root.crt'
# Require TLS 1.2 minimum (aligns with edge + internal client policy).
ssl_min_protocol_version = 'TLSv1.2'
# Log every failed SSL handshake — noisy but essential for spotting rogue
# clients during mTLS rollout.
log_connections = on
PGCONF

# Rewrite pg_hba.conf so plaintext connections from the network are rejected.
# local + 127.0.0.1 remain for the postgres entrypoint bootstrap flows.
cat > "${PGDATA}/pg_hba.conf" <<'HBA'
# TYPE  DATABASE  USER  ADDRESS        METHOD
# Local socket — used by the postgres docker-entrypoint itself for init.
local   all       all                  trust
# Loopback — postgres image runs its own bootstrap on 127.0.0.1.
host    all       all   127.0.0.1/32   trust
host    all       all   ::1/128        trust
# Everything else must come in over TLS with a client cert signed by our
# internal CA, AND present a valid scram-sha-256 password. Three factors.
hostssl all       all   0.0.0.0/0      scram-sha-256  clientcert=verify-ca
hostssl all       all   ::/0           scram-sha-256  clientcert=verify-ca
# Defence in depth — explicitly reject any plaintext attempt.
hostnossl all     all   0.0.0.0/0      reject
hostnossl all     all   ::/0           reject
HBA

chown postgres:postgres "${PGDATA}/pg_hba.conf"
chmod 0600 "${PGDATA}/pg_hba.conf"

echo "[05-enable-ssl] Done. Postgres will require TLS + client cert for network connections."
