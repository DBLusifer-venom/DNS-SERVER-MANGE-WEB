# SecureDNS Manager

Organization DNS management web tool for Linux servers running
[BIND9](https://www.isc.org/bind/) — free, distro-bundled, no vendor
software, no subscriptions, no agents on the DNS servers.

See [PLAN.md](PLAN.md) for the full architecture and roadmap.

## Status

**Phase 0 complete**: backend (FastAPI) + auth (Argon2id, JWT, refresh tokens,
lockout) + users CRUD + audit log + Vue 3 frontend (login, dashboard, users,
audit).

**Phase 1a complete**: pure-Python rndc client (isccc protocol, TSIG
HMAC-SHA256/384/512, vendored from ISC's python-rndc, MPL-2.0), server
registration with encrypted TSIG keys, connectivity testing (`rndc status`),
servers page in the UI. Phase 1b (zone registry via `rndc addzone`) is next.

**Security hardening round complete** (from external review):
- Mandatory `SECRET_KEY`/`FERNET_KEY`/`ADMIN_PASSWORD`; startup refuses
  insecure or placeholder values; Swagger/docs disabled in production
- Destination policy: DNS server hosts must resolve inside
  `DNS_MANAGEMENT_NETWORKS`; loopback/link-local/multicast/metadata ranges
  denied (loopback allowed only in development)
- HMAC-MD5 and HMAC-SHA1 removed; SHA-256/384/512 only
- JWT no longer carries the role claim (database is authoritative)
- Refresh tokens moved to HttpOnly + Secure + SameSite=strict cookies;
  access token lives in memory only (no localStorage)
- Server-level RBAC: operators only see/manage assigned servers
- Stricter systemd sandboxing + nginx CSP/referrer/permissions headers

**Hardening round 2 complete** (second external review pass):
- Token families: replaying a rotated-out refresh token revokes the
  entire family and is audited (`auth.token_reuse`)
- Login rate limiting: per-IP and per-username sliding windows (429 +
  Retry-After) in addition to account lockout
- Explicit per-server IP pinning: the IPs resolved at registration are
  stored on the Server record and re-verified on every connection
  (anti-DNS-rebinding); host changes re-pin automatically

## Security model

- **Startup**: in production the app refuses to start unless
  `SECRET_KEY`, `FERNET_KEY`, `ADMIN_PASSWORD` and
  `DNS_MANAGEMENT_NETWORKS` are set to real values (placeholders rejected).
- **Sessions**: Argon2id passwords; short-lived JWT access token (memory
  only in the browser) + rotated, revocable refresh token in an HttpOnly
  cookie; per-account lockout after failed logins; per-IP and per-username
  sliding-window rate limiting on login (429 + Retry-After). Replaying a
  rotated-out refresh token revokes the whole token family and is audited.
- **Server destinations**: every registered DNS server's resolved IPs must
  fall inside `DNS_MANAGEMENT_NETWORKS`; denied networks (link-local,
  multicast, loopback in production, test ranges) are refused at
  registration, update, and every rndc connect. The exact IPs resolved at
  registration are pinned to the Server record and re-verified on every
  connection (anti-DNS-rebinding).
- **Keys**: rndc control and dynamic-update TSIG keys are stored separately
  and encrypted at rest (Fernet). Use distinct keys per function on the
  BIND side too (rndc-control vs dns-update vs axfr-read).
- **RBAC**: admin (everything), operator (assigned servers only), viewer
  (read-only dashboards). Every mutation is written to the audit log.

## Development (Windows/macOS/Linux)

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # adjust secrets
uvicorn app.main:app --reload --port 8000
```

On first startup the bootstrap admin from `ADMIN_USERNAME`/`ADMIN_PASSWORD`
in `.env` is created. Set a strong password — the app refuses known
placeholder values.

### Tests

```bash
cd backend
python -m pytest tests -q
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api -> :8000
npm run build      # production build to dist/
```

## Production (bare metal, Linux)

Prereqs: Python 3.11+, Node 20+ (build once), optionally PostgreSQL,
nginx, certbot.

1. Create service user and layout:

   ```bash
   sudo useradd -r -m -d /opt/secure-dns -s /usr/sbin/nologin securedns
   ```

2. Deploy code to `/opt/secure-dns` (backend + frontend/dist).

3. Backend:

   ```bash
   cd /opt/secure-dns/backend
   sudo -u securedns python3 -m venv /opt/secure-dns/venv
   sudo -u securedns /opt/secure-dns/venv/bin/pip install -r requirements.txt
   # set real SECRET_KEY + FERNET_KEY + ADMIN_PASSWORD in .env
   ```

   Optional Postgres: `createdb secure_dns` and set `DATABASE_URL`.

4. Install systemd unit and enable:

   ```bash
   sudo cp deploy/systemd/secure-dns-api.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now secure-dns-api
   ```

5. nginx + TLS: copy `deploy/nginx/secure-dns.conf`, adjust
   `server_name`/cert paths, `certbot --nginx` for a real cert.

6. Firewall: DNS servers must allow HTTPS (443) from the admin host.
   rndc port 953 (and TCP 53 for dynamic updates) should only be reachable
   from this host.

## API overview

| Method | Path | Access |
|--------|------|--------|
| POST | `/api/auth/login` | public (sets HttpOnly refresh cookie) |
| POST | `/api/auth/refresh` | public (cookie or body token; rotated) |
| POST | `/api/auth/logout` | authed |
| GET | `/api/auth/me` | authed |
| GET/POST | `/api/users` | admin |
| PATCH/DELETE | `/api/users/{id}` | admin |
| GET | `/api/servers` | admin (all) / operator (assigned) |
| POST | `/api/servers` | admin |
| PATCH/DELETE | `/api/servers/{id}` | admin |
| POST | `/api/servers/{id}/test` | admin / assigned operator |
| GET/PUT | `/api/servers/{id}/assignments` | admin |
| GET | `/api/audit` | admin/operator |
| GET | `/api/health` | public |

Interactive docs: `http://localhost:8000/docs`

## BIND9 server-side setup (per DNS server)

Use **separate TSIG keys per function** (blast-radius containment):

1. Generate keys:
   ```bash
   tsig-keygen -a hmac-sha256 rndc-control-key
   tsig-keygen -a hmac-sha256 dns-update-key
   tsig-keygen -a hmac-sha256 axfr-read-key   # when zone reading lands
   ```
2. In `named.conf`:

```named.conf
options {
    allow-new-zones yes;   # required for rndc addzone
};

controls {
    inet 0.0.0.0 port 953 allow { <admin-host-ip>; } keys { "rndc-control-key"; };
};

key "rndc-control-key" { algorithm hmac-sha256; secret "BASE64..."; };
key "dns-update-key"   { algorithm hmac-sha256; secret "BASE64..."; };
key "axfr-read-key"    { algorithm hmac-sha256; secret "BASE64..."; };
```

3. Allow the admin host through the firewall to port 953 (and TCP 53 for
   dynamic updates once Phase 1b/1c land).
4. Register the server in the UI with key names + base64 secrets. Only
   HMAC-SHA256/384/512 are accepted.