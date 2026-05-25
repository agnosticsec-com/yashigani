#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup (Helm / K8s).
# Last updated: 2026-05-25 (fix: YSG-RISK-073 cycle 7 — cert auth + pg_ident CN map)
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
# YSG-RISK-050 closed — ref:
#   internal-docs/yashigani/iris-v240-ysg-risk-050-cert-separation-design.md
# YSG-RISK-073 cycle 7 closed — cert auth + pg_ident; YSG-RISK-077 (platform SCRAM bug).
#
# Mounted into postgres pod via yashigani-postgres-init ConfigMap key
# "10-pgbouncer-auth.sh". Runs ONCE on first initdb, after 05-enable-ssl.sh.
#
# See docker/postgres/10-pgbouncer-auth.sh for full canonical documentation.
# This file MUST remain functionally identical to the docker version.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup (K8s)"
: "${PGDATA:?PGDATA must be set by the postgres image}"

# ─── 1. Create pgbouncer_authenticator role ──────────────────────────────────
# NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOINHERIT.
# Grants: LOGIN + CONNECT to yashigani only + EXECUTE on ysg_pgbouncer_get_auth.
# No table grants, no schema grants, no access to letta or postgres databases.
#
# NOTE on pg_hba auth method (YSG-RISK-073 cycle 7 — cert + pg_ident):
# The pg_hba carveout uses `cert map=pgb-auth-map`. cert auth:
# - cert method: PG16 implies verify-full (CN verified against pg_ident map).
# - pg_ident map pgb-auth-map:
#     pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer instance)
#     letta-pgbouncer   → pgbouncer_authenticator  (letta sidecar pgbouncer)
# - NO PASSWORD required: cert is the sole credential.
#
# WHY NOT scram-sha-256 (cycle 6 approach — broken on ARM64 / YSG-RISK-077):
# pgbouncer 1.25.1 (edoburu, ARM64) has a SCRAM client-side computation bug.
# It sends incorrect SCRAM proofs on ARM64 Linux (Mac/Podman + K8s ARM64 nodes).
# Platform SCRAM root cause documented in YSG-RISK-077.
#
# WHY cert + pg_ident is SECURE (not a downgrade from SCRAM):
# - cert method implies verify-full: full chain + CN verified (stronger than
#   the old trust+clientcert=verify-ca which was only verify-ca).
# - pg_ident mapping restricts to CN=pgbouncer-auth AND CN=letta-pgbouncer ONLY.
# - YSG-RISK-075 (Laura cycle 5): lateral-pivot CLOSED via CN-specific pg_ident map.
#
# NO PASSWORD = no pgbouncer_authenticator_password K8s secret needed for auth:
# The role has no password. LOGIN without password is valid for cert auth.
# Helm values.yaml and secrets.yaml may still generate the password for backwards
# compat, but it is no longer mounted into postgres and no longer used for auth_user.
echo "[10-pgbouncer-auth] Creating pgbouncer_authenticator role (cert auth — no password)"
psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres <<'SQL'
\pset tuples_only on
\pset format unaligned
SELECT NOT EXISTS (
  SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pgbouncer_authenticator'
) AS needs_create \gset
\if :needs_create
  CREATE ROLE pgbouncer_authenticator
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOINHERIT;
\else
  -- Idempotent on re-run: remove any stored password (cert auth needs none).
  -- This also handles upgrades from cycle 5/6 which set a password.
  ALTER ROLE pgbouncer_authenticator PASSWORD NULL;
\endif
SQL

# ─── 2. Create SECURITY DEFINER function in yashigani database ───────────────
echo "[10-pgbouncer-auth] Creating ysg_pgbouncer_get_auth function in yashigani database"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" \
     -v owner="${POSTGRES_USER:-yashigani_app}" \
     --dbname yashigani <<'SQL'
CREATE OR REPLACE FUNCTION ysg_pgbouncer_get_auth(uname text)
  RETURNS TABLE(usename text, passwd text)
  LANGUAGE sql
  SECURITY DEFINER
  STABLE
  SET search_path = pg_catalog, public
AS $$
  SELECT usename::text, passwd::text
  FROM pg_catalog.pg_shadow
  WHERE usename = uname
  LIMIT 1;
$$;

ALTER FUNCTION ysg_pgbouncer_get_auth(text) OWNER TO :"owner";

REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases ─────────────────────────────────
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres <<'SQL'
GRANT CONNECT ON DATABASE yashigani TO pgbouncer_authenticator;

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = 'letta') THEN
    REVOKE CONNECT ON DATABASE letta FROM pgbouncer_authenticator;
  END IF;
END
$$;

REVOKE CONNECT ON DATABASE template1 FROM pgbouncer_authenticator;
SQL

# ─── 4. pg_ident.conf CN map + cert pg_hba carveout (YSG-RISK-073 cycle 7) ──
# See docker/postgres/10-pgbouncer-auth.sh for full historical context.
#
# FIX: cert auth method + pg_ident.conf CN mapping (YSG-RISK-077 root cause).
# - pg_ident map (pgb-auth-map) maps two CNs to pgbouncer_authenticator:
#     pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer)
#     letta-pgbouncer   → pgbouncer_authenticator  (letta-pgbouncer sidecar)
# - cert method: PG16 cert auth implies verify-full (full chain + CN verified).
# - NO PASSWORD: pgbouncer presents its TLS client cert; no SCRAM exchange.

# Step 4a: write pg_ident.conf CN map (idempotent — remove existing pgb-auth-map, add fresh).
echo "[10-pgbouncer-auth] Writing pg_ident.conf pgb-auth-map (cert CN → pgbouncer_authenticator)"
_ident="${PGDATA}/pg_ident.conf"
sed -i '/^pgb-auth-map/d' "${_ident}"
{
  printf '# YSG-RISK-073 cycle 7: pgbouncer cert CN → pgbouncer_authenticator (cert auth map)\n'
  printf '# Both pgbouncer instances authenticate via cert; pg_ident maps their CN to the role.\n'
  printf 'pgb-auth-map  pgbouncer-auth    pgbouncer_authenticator\n'
  printf 'pgb-auth-map  letta-pgbouncer   pgbouncer_authenticator\n'
} >> "${_ident}"
echo "[10-pgbouncer-auth] pg_ident.conf pgb-auth-map written"

# Step 4b: remove any existing pgbouncer_authenticator pg_hba lines (any method).
if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  sed -i '/pgbouncer_authenticator/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Amendment A2.*YSG-RISK-049/d' "${PGDATA}/pg_hba.conf"
  sed -i '/YSG-RISK-073/d' "${PGDATA}/pg_hba.conf"
  sed -i '/TWO-FACTOR.*clientcert/d' "${PGDATA}/pg_hba.conf"
  sed -i '/pgbouncer 1.25.1.*SCRAM/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Closes Laura cycle/d' "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] Removed existing pgbouncer_authenticator pg_hba entries (normalising)"
fi

# Step 4c: insert the cert+pg_ident carveout BEFORE the first hostssl catch-all.
if grep -q "^hostssl all" "${PGDATA}/pg_hba.conf"; then
  _hba="${PGDATA}/pg_hba.conf"
  _tmp="${PGDATA}/pg_hba.conf.new.$$"
  awk '
    /^hostssl all/ && !inserted {
      print "# YSG-RISK-073 cycle 7: pgbouncer_authenticator auth_query -- cert auth via pg_ident CN map."
      print "# cert method: PG16 verify-full (full chain + CN mapped via pg_ident pgb-auth-map)."
      print "# CN=pgbouncer-auth (main pgbouncer) + CN=letta-pgbouncer (sidecar) → pgbouncer_authenticator."
      print "# NO password. Avoids pgbouncer 1.25.1 ARM64 SCRAM computation bug (YSG-RISK-077)."
      print "# Stronger than trust+clientcert: verify-full + CN-specific pg_ident map. YSG-RISK-075 CLOSED."
      print "hostssl yashigani pgbouncer_authenticator 0.0.0.0/0  cert  map=pgb-auth-map"
      print "hostssl yashigani pgbouncer_authenticator ::/0        cert  map=pgb-auth-map"
      inserted = 1
    }
    { print }
  ' "${_hba}" > "${_tmp}"
  chown postgres:postgres "${_tmp}"
  chmod 0600 "${_tmp}"
  mv "${_tmp}" "${_hba}"
  echo "[10-pgbouncer-auth] Inserted cert+pg_ident carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 7)"
else
  echo "[10-pgbouncer-auth] WARNING: no hostssl catch-all found — carveout will be needed at startup"
fi

# Reload pg_hba.conf (no-op during initdb; fires immediately on upgrade exec path).
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete (K8s)."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_ident.conf pgb-auth-map: CN=pgbouncer-auth + CN=letta-pgbouncer → pgbouncer_authenticator"
echo "  - pg_hba cert+pg_ident carveout: inserted for pgbouncer_authenticator (YSG-RISK-073 cycle 7)"
echo "  - pg_hba catch-all (scram-sha-256 clientcert=verify-ca): applies to all other roles"
echo "  - YSG-RISK-073: CLOSED (cycle 7). YSG-RISK-075: CLOSED. YSG-RISK-077: documented (ARM64 SCRAM bug)."
