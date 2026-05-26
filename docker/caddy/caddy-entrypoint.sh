#!/bin/sh
# Yashigani — Caddy egress restriction entrypoint
# YSG-RISK-061 (2026-05-25): iptables OUTPUT allowlist
# BUG-V243-CADDY-IPV6-IPTABLES (2026-05-26): IPv6 BLOCKED (not allowlisted)
#
# PURPOSE
#   Enforce a network egress allowlist for the Caddy container before starting
#   the Caddy process. Blocks all outbound TCP/UDP except to explicitly
#   permitted destinations.
#
# ADDRESS FAMILY POSTURE — Tiago directive 2026-05-26
#   Yashigani is IPv4-only by design. IPv6 is BLOCKED (DROP policy with no
#   allowlist rules), not supported. Rationale: IPv6 never gained meaningful
#   deployment traction in the ecosystems Yashigani targets, and the industry
#   is moving toward IPv7. Supporting IPv6 inside the ring-fence adds attack
#   surface (parallel egress path) without proportional value. All IPv6 OUTPUT
#   from the Caddy container is dropped at the ip6tables policy level —
#   there is no per-host AAAA allowlist, no ACME-over-IPv6 path, no operator
#   override for IPv6 destinations. If an operator NEEDS IPv6 connectivity,
#   they MUST disable Yashigani's ring-fence (out of supported scope) or
#   front Yashigani with an IPv6 → IPv4 NAT64 gateway (also out of scope).
#
# LEGITIMATE CADDY EGRESS DESTINATIONS
#   1. Loopback (lo) — admin unix socket healthchecks
#   2. In-mesh Docker bridge networks (caddy_internal, obs, edge) — resolved at
#      runtime from `ip route` kernel routes; no DNS lookup required
#   3. Docker embedded DNS — 127.0.0.11:53/udp (always localhost)
#   4. ACME providers — resolved at startup (acme mode only; controlled by
#      YASHIGANI_TLS_MODE=acme). Default allowlist:
#      acme-v02.api.letsencrypt.org:443
#      acme-staging-v02.api.letsencrypt.org:443
#   5. OCSP stapling — http://r11.o.lencr.org:80 + r10.o.lencr.org:80 (Let's
#      Encrypt OCSP; only in acme mode). Caddy auto-staples OCSP.
#   6. ESTABLISHED/RELATED — return traffic for inbound client connections on
#      :80/:443 (these are response packets, not new connections)
#   Operators may extend the ACME list via YASHIGANI_CADDY_EGRESS_ALLOWLIST env.
#
# DESIGN NOTES
#   - NET_ADMIN capability is required for iptables OUTPUT manipulation.
#   - If iptables fails (e.g. Podman rootless without --privileged), we log a
#     warning and start Caddy WITHOUT restrictions (graceful degradation).
#   - Docker bridge subnets vary per deployment; we enumerate them at startup
#     from the kernel routing table to avoid hardcoding CIDRs.
#   - The ESTABLISHED/RELATED rule handles response packets for Caddy's own
#     inbound listeners (:80/:443/:8444/:8445) — without it, Caddy cannot send
#     replies back to clients even if OUTPUT is DROP.
#   - LOG target before final DROP: aids debugging when a new upstream is added
#     to Caddyfile without updating this allowlist.
#   - Rootless Podman: the process runs in a user network namespace. iptables
#     may require /proc/net/ip_tables_names or nft backend. If iptables -P OUTPUT
#     DROP fails, we fall through gracefully (logged as WARN).
#
# TRADE-OFF (NET_ADMIN)
#   NET_ADMIN was previously absent (cap_add: [NET_BIND_SERVICE] only).
#   NET_ADMIN allows iptables manipulation within the container's network
#   namespace — it does NOT grant access to the host network stack.
#   Docker/Podman enforce this via Linux network namespaces. Accepted per
#   YSG-RISK-061 (Tiago 2026-05-25).
#
# OPERATOR OVERRIDE
#   YASHIGANI_CADDY_EGRESS_ALLOWLIST — comma-separated list of host:port pairs
#   to add to the ACME allowlist. Example:
#     YASHIGANI_CADDY_EGRESS_ALLOWLIST=acme-v02.api.letsencrypt.org:443,operator-ca.example:443
#   Default: acme-v02.api.letsencrypt.org:443,acme-staging-v02.api.letsencrypt.org:443

set -eu

log() {
    printf '[caddy-entrypoint] %s\n' "$*" >&2
}

warn() {
    printf '[caddy-entrypoint] WARN: %s\n' "$*" >&2
}

apply_egress_rules() {
    # ── Step 1: probe NET_ADMIN availability (IPv4) ──────────────────────────
    # Try to set OUTPUT default policy. If this fails, we have no NET_ADMIN and
    # must skip all iptables setup. Caddy still starts — just without egress
    # restrictions (documented limitation for rootless Podman).
    if ! iptables -P OUTPUT DROP 2>/dev/null; then
        warn "iptables OUTPUT policy modification failed — container lacks NET_ADMIN."
        warn "Egress restrictions NOT applied. Caddy starts without OUTPUT allowlist."
        warn "Rootless Podman limitation: re-run with --cap-add NET_ADMIN or use K8s NetworkPolicy."
        return 0
    fi
    log "NET_ADMIN available — applying iptables OUTPUT allowlist (IPv4)."

    # ── Step 1b: BLOCK IPv6 entirely ────────────────────────────────────────
    # Tiago directive 2026-05-26: Yashigani is IPv4-only by design. IPv6 is
    # blocked at the ip6tables policy level — no per-host allowlist, no AAAA
    # ACME path, no operator override for IPv6. If ip6tables itself is
    # unavailable in this namespace (kernel CONFIG_IP6_NF_IPTABLES absent,
    # IPv6 disabled via sysctl, NET_ADMIN missing for v6) that's actually
    # the SAFER state because IPv6 has no functional stack — log as INFO,
    # not WARN. If ip6tables IS available, we apply a hard DROP policy with
    # NO ACCEPT rules (not even loopback — Caddy and its in-container
    # callers use IPv4 only).
    IPV6_TABLE=0
    if ip6tables -P OUTPUT DROP 2>/dev/null; then
        IPV6_TABLE=1
        # Flush any rules that might have been inherited from another run
        # (defensive — the OUTPUT chain is the one we control).
        ip6tables -F OUTPUT 2>/dev/null || true
        log "ip6tables available — IPv6 OUTPUT policy = DROP (Yashigani is IPv4-only by design)."
    else
        log "ip6tables not applicable — kernel/namespace has no usable IPv6 stack (this is the intended state)."
    fi

    # ── Step 2: Allow loopback (IPv4 only) ─────────────────────────────────
    # All Caddy admin socket interactions (healthcheck, reload) go via loopback.
    # IPv6 loopback (::1) is deliberately NOT allowed — Caddy and its callers
    # use 127.0.0.1.
    iptables -A OUTPUT -o lo -j ACCEPT
    log "egress allow: loopback (IPv4 only — IPv6 blocked by policy)"

    # ── Step 3: Allow ESTABLISHED/RELATED (IPv4 only) ────────────────────────
    # Required for Caddy's inbound IPv4 listeners (:80/:443/:8444/:8445) to send
    # response packets. Without this, SYN-ACK and data packets to clients are
    # dropped by the OUTPUT chain. IPv6 ESTABLISHED is NOT allowed — Caddy's
    # listeners should not accept IPv6 (Caddyfile binds IPv4); any IPv6 inbound
    # is a misconfiguration and we will not silently support response traffic
    # for it.
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log "egress allow: ESTABLISHED,RELATED (IPv4 only — response packets for inbound listeners)"

    # ── Step 4: Allow Docker embedded DNS (IPv4 only) ──────────────────────
    # Docker's embedded resolver is 127.0.0.11 (IPv4-only by Docker design).
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    log "egress allow: DNS → 127.0.0.11:53 (Docker embedded resolver, IPv4 only)"

    # ── Step 5: Allow Docker bridge subnets (IPv4 only) ────────────────────
    # Caddy proxies to in-mesh services (gateway, backoffice, open-webui,
    # grafana, prometheus) on Docker bridge networks. We enumerate IPv4
    # subnets from the kernel routing table. IPv6 routes (if any — `ip -6
    # route show`) are deliberately ignored; compose networks are configured
    # with enable_ipv6: false to prevent IPv6 mesh routing entirely.
    bridge_subnets_v4=$(ip route show 2>/dev/null | awk '/proto kernel/ {print $1}')
    if [ -n "$bridge_subnets_v4" ]; then
        for subnet in $bridge_subnets_v4; do
            iptables -A OUTPUT -d "$subnet" -j ACCEPT
            log "egress allow: Docker bridge subnet $subnet (IPv4)"
        done
    else
        warn "No IPv4 bridge subnets found via ip route — in-mesh egress may be blocked."
    fi

    # ── Step 6: Allow ACME providers + operator allowlist (IPv4 only) ────
    # Default ACME list: Let's Encrypt prod + staging + OCSP responders.
    # Operator overrides via YASHIGANI_CADDY_EGRESS_ALLOWLIST (comma-separated
    # host:port pairs) are appended.
    #
    # IPv6 BLOCK posture: `getent ahosts` returns both A and AAAA records.
    # The case-statement below SKIPS AAAA results silently — IPv6 destinations
    # are blocked at the ip6tables policy level (Step 1b), not allowlisted.
    # This is the BUG-V243-CADDY-IPV6-IPTABLES fix: before the fix, the loop
    # fed AAAA records to iptables (IPv4-only) which crashed under set -e.

    DEFAULT_ACME_HOSTS="acme-v02.api.letsencrypt.org:443 acme-staging-v02.api.letsencrypt.org:443 r10.o.lencr.org:80 r11.o.lencr.org:80 r12.o.lencr.org:80 e5.o.lencr.org:80 e6.o.lencr.org:80"
    OPERATOR_EXTRA="${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}"
    full_allowlist="${DEFAULT_ACME_HOSTS}"
    if [ -n "$OPERATOR_EXTRA" ]; then
        extra_space=$(printf '%s' "$OPERATOR_EXTRA" | tr ',' ' ')
        full_allowlist="${full_allowlist} ${extra_space}"
    fi

    resolved_v4=0
    skipped_v6=0
    for host_port in $full_allowlist; do
        host="${host_port%:*}"
        port="${host_port##*:}"
        # Resolve to ALL families (A + AAAA), then SKIP IPv6 results.
        # IPv6 destinations are blocked at the ip6tables policy level.
        all_ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        if [ -z "$all_ips" ]; then
            warn "Could not resolve $host — skipping egress rule for $host:$port"
            continue
        fi
        for ip in $all_ips; do
            case "$ip" in
                *:*)
                    # IPv6 — BLOCKED by ip6tables policy DROP. Skip silently
                    # in the iptables loop. Do NOT add to ip6tables either —
                    # IPv6 is not a supported address family in Yashigani.
                    skipped_v6=$((skipped_v6 + 1))
                    ;;
                *.*)
                    iptables -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
                    log "egress allow: $host ($ip) :$port (IPv4)"
                    resolved_v4=$((resolved_v4 + 1))
                    ;;
                *)
                    warn "Unrecognised address family for $host: $ip — skipping."
                    ;;
            esac
        done
    done
    log "ACME/OCSP/operator egress: $resolved_v4 IPv4 rules added; $skipped_v6 IPv6 destinations BLOCKED by policy."

    # ── Step 7: LOG then DROP (both tables) ──────────────────────────────
    # IPv4 LOG: any blocked IPv4 egress appears in the host kernel log under
    # CADDY_EGRESS_BLOCKED_V4 prefix.
    iptables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V4: " --log-level 4 2>/dev/null \
        && log "egress LOG rule installed (IPv4, CADDY_EGRESS_BLOCKED_V4 prefix)" \
        || warn "iptables LOG target unavailable — blocked IPv4 egress will not be logged (DROP still applies)"
    iptables -A OUTPUT -j DROP
    log "egress OUTPUT DROP applied (IPv4) — allowlist active."

    # IPv6 LOG: any IPv6 egress attempt (which there shouldn't be in a healthy
    # Yashigani install) logs under CADDY_EGRESS_BLOCKED_V6. This is the
    # canary for IPv6-bypass attempts — if it fires, an attacker or
    # misconfigured service is trying IPv6 egress.
    if [ "$IPV6_TABLE" = "1" ]; then
        ip6tables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V6: " --log-level 4 2>/dev/null \
            && log "egress LOG rule installed (IPv6, CADDY_EGRESS_BLOCKED_V6 prefix — fires on bypass attempts)" \
            || warn "ip6tables LOG target unavailable — IPv6 bypass attempts will not be logged (policy DROP still applies)"
        # No need to -A OUTPUT -j DROP — policy is already DROP and there are
        # zero ACCEPT rules. Adding an explicit -j DROP would shadow the LOG.
    fi

    log "Effective iptables OUTPUT chain (IPv4):"
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done
    if [ "$IPV6_TABLE" = "1" ]; then
        log "Effective ip6tables OUTPUT chain (IPv6, all-DROP):"
        ip6tables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
            log "  $line"
        done
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Caddy egress entrypoint starting (YSG-RISK-061)"
log "TLS mode: ${YASHIGANI_TLS_MODE:-acme} (informational)"
if [ -n "${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}" ]; then
    log "Operator EGRESS_ALLOWLIST: ${YASHIGANI_CADDY_EGRESS_ALLOWLIST}"
fi

apply_egress_rules

log "Starting Caddy..."
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
