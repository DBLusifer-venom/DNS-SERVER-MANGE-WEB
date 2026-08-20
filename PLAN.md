# SecureDNS Manager — Project Plan

Organization DNS management web tool for Linux servers running
[BIND9](https://www.isc.org/bind/) — the free, distro-bundled DNS server.
No vendor software, no subscriptions, no agents on the DNS servers.

## 1. Goals

- Central web UI to manage DNS zones/records on **independent** BIND9 servers
- Control plane via **rndc** over TCP (TSIG-authenticated, default port 953)
- Data plane via **RFC 2136 dynamic updates** (nsupdate protocol, TSIG, TCP 53)
- DNSSEC via BIND inline-signing (`dnssec-policy`) + DS export
- Role-based access control with the tool's own user accounts
- Full audit trail of every change
- Monitoring + alerting on server health and zone status
- Agentless: no SSH access to DNS servers required, TSIG keys only

## 2. Architecture

```
Browser ──HTTPS──> Nginx (TLS termination)
                        │
                Web App (central, one deployment)
        ┌────────────────┼────────────────────┐
  FastAPI backend   Vue 3 frontend      PostgreSQL 15
  (RBAC, audit,     (zone/record        (users, roles,
   orchestration)    editor, dash)       audit, registry)
        │
   ┌────┴────┬────────────┬───────────────┐
 DNS Srv A  DNS Srv B   ... DNS Srv N      (BIND9)
 (BIND9)         │
   │        rndc :953 (TSIG, control: addzone/delzone/status/zonestatus)
   │        TCP 53  (TSIG, RFC 2136 dynamic updates: record CRUD)
   │        TCP 53  (AXFR/query: zone contents, DNSKEY for DS export)
```

- **No agent on DNS servers** — only TSIG keys + `allow-new-zones yes;`
  + `allow-update`/`allow-transfer` scoped to the tool's IP
- Servers are independent: each zone edit is pushed to one selected server
- The tool's database is the zone **registry**; zones are created on BIND
  via `rndc addzone` (with inline-signing + dnssec-policy by default)
- Zone contents are read via AXFR and edited via RFC 2136 updates

## 3. Tech Stack

| Layer      | Choice |
|------------|--------|
| Backend    | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2 |
| DB         | PostgreSQL 15 |
| Frontend   | Vue 3 (Vite), Pinia, Vue Router, Bootstrap |
| Auth       | Argon2id password hashing, short-lived JWT + refresh |
| Secrets    | Fernet (symmetric AES) encryption of stored TSIG keys |
| Deploy     | systemd units + nginx (bare metal) |
| DNS control| Custom rndc client (pure Python, HMAC-SHA256, TCP 953) |
| DNS data   | dnspython — RFC 2136 updates, AXFR, queries (TSIG, TCP 53) |

## 4. Database Schema

```
users        id, username, email, password_hash, role, active, created_at
servers      id, name, host, rndc_port, rndc_key_name, rndc_secret_enc,
             update_port, update_key_name, update_secret_enc, status,
             last_checked_at, version, notes
zones        id, server_id FK, name, kind, dnssec_enabled, serial,
             soa_rname, synced_at                  (registry: what the tool manages)
records      id, zone_id FK, name, type, ttl, content, disabled,
             created_by, updated_at               (cache of last AXFR)
audit_log    id, user_id FK, action, resource_type, resource_id,
             payload, ip_address, created_at
alerts       id, server_id FK, rule_type, threshold, channel, enabled
events       id, server_id FK, level, message, created_at
users_token  id, user_id FK, refresh_token_hash, expires_at, revoked
```

## 5. REST API (backend)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST   | /api/auth/login, /refresh, /logout | Auth |
| GET    | /api/auth/me | Current user |
| CRUD   | /api/users | User management (admin) |
| CRUD   | /api/servers | Register/test DNS servers |
| POST   | /api/servers/{id}/test | rndc connectivity + version |
| GET    | /api/servers/{id}/zones | Registry zones + live zonestatus |
| POST   | /api/servers/{id}/zones | Create zone (rndc addzone) |
| DELETE | /api/servers/{id}/zones/{zone} | Delete zone (rndc delzone) |
| GET    | /api/servers/{id}/zones/{zone}/records | Zone contents (AXFR) |
| POST   | /api/servers/{id}/zones/{zone}/records | Add/update/delete RRset (RFC 2136) |
| GET    | /api/servers/{id}/zones/{zone}/dnssec/ds | DS export (from DNSKEY) |
| GET    | /api/servers/{id}/zones/{zone}/dnssec/status | rndc dnssec -status |
| GET    | /api/servers/{id}/stats | rndc status snapshot |
| GET    | /api/monitoring/health | Server health checks |
| GET    | /api/audit | Audit log (filterable) |
| CRUD   | /api/alerts | Alert rules |

## 6. Feature Phases + Estimates

| Phase | Scope | Days |
|-------|-------|------|
| 0 | Auth, users, audit, UI shell (DONE) | 3 |
| 1a | rndc client + TSIG, server CRUD + connectivity test | 4 |
| 1b | Zone registry: addzone/delzone, zonestatus, zone list | 4 |
| 1c | Record editor: AXFR read, RFC 2136 add/update/delete | 6 |
| 2 | Editor polish: validation, multi-record view, search | 4 |
| 3 | DNSSEC: inline-signing defaults, DS export, key status | 4 |
| 4 | RBAC server assignment + audit polish | 3 |
| 5 | Monitoring/alerts: rndc status polling, health checks, email | 5 |
| 6 | Hardening: HTTPS, rate limiting, unit tests, deploy docs | 4 |
| | **Total** | **~37 dev days** |

## 7. Roles (RBAC)

| Role    | Permissions |
|---------|-------------|
| admin   | Everything incl. users, servers, assignments, alerts, audit |
| operator| Zones/records/DNSSEC **on assigned servers only** |
| viewer  | Read-only dashboards, zones, records |

Implementations: `server_assignments` table; operators see only their
assigned servers; object-level checks on every server endpoint.

## 8. Security Requirements

- HTTPS-only (nginx TLS termination, HSTS, CSP, referrer/permissions headers)
- Startup refuses insecure config: `SECRET_KEY`/`FERNET_KEY`/`ADMIN_PASSWORD`
  mandatory, placeholder values rejected; Swagger/docs off in production
- Argon2id password hashing; short-lived JWT (no role claim — DB is
  authoritative) + rotated, revocable refresh tokens in HttpOnly
  Secure SameSite cookies; token-family revocation on reuse
- TSIG keys encrypted at rest (Fernet); never exposed via API;
  HMAC-SHA256/384/512 only (no MD5/SHA1)
- Destination policy: DNS server IPs must resolve inside
  `DNS_MANAGEMENT_NETWORKS`; link-local/multicast/metadata/loopback
  (prod) denied — no SSRF surface; per-server IP pinning with
  re-verification on every connect (anti-DNS-rebinding)
- Rate limiting on login: per-IP + per-username sliding windows,
  account lockout (Redis-backed when HA)
- RBAC enforced middleware on every endpoint incl. object-level
  server assignment checks
- Full audit of all mutations: who/what/when/from-IP/payload;
  before/after payloads for DNS record changes
- Firewall: rndc :953 and TCP 53 reachable only from the admin host
- No default credentials; first-run admin bootstrap flow

## 9. Deployment

- Docker Compose: `web` (FastAPI + static Vue build), `db` (Postgres), `nginx`
- Or systemd units on a single admin host
- Postgres backups scheduled; audit log retained ≥ 1 year

## 10. Risks / Open Questions

- rndc protocol is custom (isccc over TCP + TSIG) — client verified against
  ISC's python-rndc and mock-server tests; real-BIND integration tests
  required before production (P1)
- No rndc "list all zones" command → tool DB is the zone registry;
  `rndc zonestatus` validates each registered zone
- AXFR for reading zone contents requires a dedicated `axfr-read-key`
  (never the rndc control key)
- Test environment needed: 2 BIND9 VMs/containers before integration work
- Alert channels: SMTP email first, webhook (Slack/Teams) optional
- Rate limiting is per-account; distributed IP-based limiting + Redis
  when HA (P2)
- Audit log lives in the app DB today; SIEM/syslog export planned (P2)

## 11. BIND9 server-side requirements (per DNS server)

Separate TSIG keys per function (rndc-control / dns-update / axfr-read).

```named.conf
options {
    allow-new-zones yes;           # required for rndc addzone
    # allow-query set per zone/role: authoritative-public, -private,
    # split-horizon etc. — never blanket 'any' unless truly public
};

controls {
    inet 0.0.0.0 port 953 allow { <admin-host-ip>; } keys { "rndc-control-key"; };
};

key "rndc-control-key" { algorithm hmac-sha256; secret "BASE64..."; };
key "dns-update-key"   { algorithm hmac-sha256; secret "BASE64..."; };

# Per-zone, created by the tool via rndc addzone:
#   type master; allow-update { key "dns-update-key"; };
#   inline-signing yes; dnssec-policy "default"; zone-statistics yes;
#   allow-transfer { key "axfr-read-key"; };   # tool AXFRs zone contents
```
