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
HMAC-SHA256, vendored from ISC's python-rndc, MPL-2.0), server registration
with encrypted TSIG keys, connectivity testing (`rndc status`), servers page
in the UI. Phase 1b (zone registry via `rndc addzone`) is next.

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
in `.env` is created. **Change the default password immediately.**

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
| POST | `/api/auth/login` | public |
| POST | `/api/auth/refresh` | public (refresh token) |
| POST | `/api/auth/logout` | authed |
| GET | `/api/auth/me` | authed |
| GET/POST | `/api/users` | admin |
| PATCH/DELETE | `/api/users/{id}` | admin |
| GET | `/api/servers` | admin/operator |
| POST | `/api/servers` | admin |
| PATCH/DELETE | `/api/servers/{id}` | admin |
| POST | `/api/servers/{id}/test` | admin/operator |
| GET | `/api/audit` | admin/operator |
| GET | `/api/health` | public |

Interactive docs: `http://localhost:8000/docs`

## BIND9 server-side setup (per DNS server)

1. Generate a TSIG key: `tsig-keygen -a hmac-sha256 rndc-key`
2. In `named.conf`:

```named.conf
options {
    allow-new-zones yes;   # required for rndc addzone
};

controls {
    inet 0.0.0.0 port 953 allow { <admin-host-ip>; } keys { "rndc-key"; };
};

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BASE64...";    # from tsig-keygen
};
```

3. Allow the admin host through the firewall to port 953 (and TCP 53 for
   dynamic updates once Phase 1b/1c land).
4. Register the server in the UI with the key name + base64 secret.