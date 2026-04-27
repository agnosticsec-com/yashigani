#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.23.1 — enable TLS + client-cert verification on Postgres.
# Last updated: 2026-04-27T20:40:49Z (BUG-59-01: trust intermediate CA, not root)
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
#
# PKI design: root → intermediate → leaf (two-tier).
# ssl_ca_file (root.crt) must contain the INTERMEDIATE CA, not the root.
# All service leaf certs are signed directly by the intermediate.  When
# pgbouncer presents its client cert to postgres it may not send the
# intermediate in the TLS handshake chain (behaviour varies by libssl
# version / pgbouncer version).  Seeding root.crt with the intermediate
# ensures postgres can always verify the leaf directly without requiring the
# intermediate to appear in the peer's TLS Certificate message.
#
# The root CA MUST NOT appear in this file and MUST NOT be mounted as an
# mTLS trust anchor into any workload container (design invariant, retro S1).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[05-enable-ssl] Installing server cert chain and enabling TLS"

# Fail-closed: intermediate CA cert must be present before we write anything.
: "${PGDATA:?PGDATA must be set by the postgres image}"
if [[ ! -f /run/secrets/ca_intermediate.crt ]]; then
  echo "[05-enable-ssl] FATAL: /run/secrets/ca_intermediate.crt not found — PKI bootstrap must run before postgres init" >&2
  exit 1
fi

# Postgres requires SSL material inside PGDATA and owned by the postgres user.
install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${PGDATA}/server.key"
# BUG-59-01: trust the intermediate CA (direct issuer of all leaf certs), not
# the root.  Filename "root.crt" is postgres's hardcoded ssl_ca_file name —
# the name is fixed; the content is what matters.
install -m 0640 -o postgres -g postgres /run/secrets/ca_intermediate.crt "${PGDATA}/root.crt"

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
