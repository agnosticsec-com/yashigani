# Wazuh SIEM on Linux / Docker 29.x — fixes (v2.25.1)

Status: **config restored to HTTPS + mTLS; needs an e2e validation run on the 2.25 line before release.**
The equivalent config was driven **green** in the AMD64 E2E run on **2026-05-30** (on v2.24.4).

## TL;DR

v2.25.0-prep's `docker/docker-compose.wazuh.yml` pointed the **manager**
(`INDEXER_URL`), **dashboard** (`OPENSEARCH_HOSTS` / `WAZUH_API_URL`) and all three
**healthchecks** at `http://` — while the `wazuh-indexer` image serves **TLS on 9200
by default** (the OpenSearch security plugin is ON; there is no `DISABLE_SECURITY`).
That is a **broken, plaintext-intent** configuration:

- the `http://` healthchecks never succeed against the TLS listener → containers
  flap **false-unhealthy**, and `depends_on: service_healthy` stalls the stack;
- any traffic that did flow would be **unencrypted** — unacceptable for internal
  SIEM traffic.

**Internal Wazuh traffic must be HTTPS + mTLS.** Wazuh/OpenSearch support this
natively (proven on v2.24.4) — **no TLS sidecar is needed.** This change reverses
the `http://` downgrade and carries the Docker-29.x boot fixes.

## What changed in `docker-compose.wazuh.yml`

| Area | v2.25.0-prep (wrong) | v2.25.1 (this fix) |
|---|---|---|
| manager → indexer | `INDEXER_URL: http://…` | `https://…` + filebeat mTLS (`SSL_CERTIFICATE`/`_KEY`/`_AUTHORITIES`, `FILEBEAT_SSL_VERIFICATION_MODE: full`) |
| manager cert mounts | none | `wazuh-manager_client.crt/.key` + `ca_root.crt` mounted to the paths the env already referenced |
| indexer healthcheck | `curl http://localhost:9200` | `curl -k https://localhost:9200` (200/401/403 all prove TLS + security up) |
| dashboard → indexer | `OPENSEARCH_HOSTS: http://…`, `SERVER_SSL_ENABLED:false` | `opensearch_dashboards.yml` mounted → `https://wazuh-indexer:9200` |
| dashboard → manager API | `WAZUH_API_URL: http://…` | `https://…` |

## Docker 29.x boot fixes (carried from the E2E)

1. **Volume-mount-readiness race** — the stock s6 `cont-init` runs `find`/`cp` over
   per-subdir volume mounts before they are ready (~94% of cycles on Docker 29.1.3)
   and `error_and_exit`s the boot. Fix: patched `docker/wazuh-patch/0-wazuh-init`
   logs the miss and **continues** instead of aborting. **Mount it writable** (not
   `:ro`) — s6 chmods it on boot.
2. **`cap_drop:[ALL]` vs the s6 entrypoint** — Wazuh must chown/setuid to `wazuh(999)`
   and `chroot` analysisd into `/var/ossec`. Grant minimal caps incl. **`SYS_CHROOT`**
   and **`SETPCAP`** on the manager; the indexer/dashboard need the chown/setuid set.
   `no-new-privileges:true` retained everywhere.
3. **filebeat certs never mounted** — the manager env referenced cert paths the stock
   compose never mounted, so filebeat could not establish TLS. Now mounted.
4. **dashboard had no `opensearch_dashboards.yml`** — the image ships none; mounted a
   minimal one pointing at the HTTPS indexer.

## One-time security-index init (`securityadmin`)

After the first `up`, initialise the OpenSearch security index once:

```
docker compose exec wazuh-indexer bash -c '\
  export INSTALLATION_DIR=/usr/share/wazuh-indexer; \
  JAVA_HOME=$INSTALLATION_DIR/jdk \
  $INSTALLATION_DIR/plugins/opensearch-security/tools/securityadmin.sh \
    -cd $INSTALLATION_DIR/opensearch-security/ -nhnv \
    -cacert $INSTALLATION_DIR/certs/root-ca.pem \
    -cert $INSTALLATION_DIR/certs/admin.pem \
    -key $INSTALLATION_DIR/certs/admin-key.pem -h localhost'
```

## Follow-ups before / at release

- [ ] **e2e validation run on the 2.25 line** (the green run was on v2.24.4).
- [ ] **Automate `securityadmin`** as a one-shot init container, once the admin-DN /
      admin cert wiring is confirmed against the bootstrap-issued certs.
- [ ] **Harden dashboard→indexer credentials** — `opensearch_dashboards.yml` currently
      carries the OpenSearch demo default (`admin`/`admin`); replace with the
      bootstrap-generated indexer credential (customise `internal_users.yml` + re-run
      `securityadmin`) so no default credential ships.
- [ ] Confirm the SiemSink `wazuh_api_key` (KMS) path against the HTTPS `_bulk` endpoint.
