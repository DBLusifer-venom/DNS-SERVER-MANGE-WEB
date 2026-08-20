import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DATABASE_URL"] = "sqlite:///./test_secure_dns.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["FERNET_KEY"] = base64.urlsafe_b64encode(b"f" * 32).decode()
os.environ["ADMIN_PASSWORD"] = "Test_Admin_Pass_123!"
os.environ["ADMIN_USERNAME"] = "tadmin"
os.environ["COOKIE_SECURE"] = "false"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app
from tests.mock_rndc import MockRndcServer

TEST_SECRET_B64 = base64.b64encode(b"x" * 32).decode()
BAD_SECRET_B64 = base64.b64encode(b"y" * 32).decode()


@pytest.fixture(scope="module")
def mock_rndc():
    server = MockRndcServer(TEST_SECRET_B64)
    yield server
    server.close()


@pytest.fixture(scope="module")
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def admin_token(client):
    r = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def make_server_body(name: str, host: str = "127.0.0.1", port: int = 953,
                     secret: str = TEST_SECRET_B64, algorithm: str = "sha256") -> dict:
    return {
        "name": name,
        "host": host,
        "notes": "test server",
        "rndc_port": port,
        "rndc_key_name": "rndc-key",
        "rndc_algorithm": algorithm,
        "rndc_secret": secret,
        "update_port": 53,
        "update_key_name": "update-key",
        "update_secret": TEST_SECRET_B64,
    }


def create_server(client, token, name="ns1", **overrides) -> int:
    body = make_server_body(name, **overrides)
    r = client.post("/api/servers", json=body, headers=auth(token))
    assert r.status_code == 201, r.text
    assert "secret" not in r.text.lower()  # never leak secrets
    return r.json()["id"]


def create_user(client, token, username, role="operator") -> int:
    r = client.post(
        "/api/users",
        json={"username": username, "email": f"{username}@example.com", "password": "User_Pass_123!", "role": role},
        headers=auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def login(client, username, password="User_Pass_123!") -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_create_server(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns1", port=mock_rndc.port)
    r = client.get(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["name"] == "ns1"
    assert r.json()["status"] == "unknown"
    assert r.json()["assigned_user_ids"] == []
    assert r.json()["pinned_ips"] == ["127.0.0.1"]  # explicit per-server allowlist


def test_update_host_re_pins(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns-repin", port=mock_rndc.port)
    r = client.patch(f"/api/servers/{sid}", json={"host": "127.0.0.2"}, headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["pinned_ips"] == ["127.0.0.2"]


def test_test_server_blocked_when_pins_mismatch(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns-rebind", port=mock_rndc.port)
    # Simulate DNS rebinding: pins point elsewhere than the host now resolves to
    from app.database import SessionLocal
    from app.models import Server

    db = SessionLocal()
    try:
        s = db.get(Server, sid)
        s.pinned_ips = "127.0.0.2"  # host still 127.0.0.1
        db.commit()
    finally:
        db.close()
    r = client.post(f"/api/servers/{sid}/test", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "re-pin" in r.json()["detail"]


def test_test_server_ok(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns-ok", port=mock_rndc.port)
    r = client.post(f"/api/servers/{sid}/test", headers=auth(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert "mock-bind" in body["version"]
    assert "up and running" in body["status_text"]

    r = client.get(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.json()["status"] == "ok"
    assert "mock-bind" in r.json()["version"]


def test_test_server_bad_secret(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns-bad", port=mock_rndc.port, secret=BAD_SECRET_B64)
    r = client.post(f"/api/servers/{sid}/test", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "failed" in r.json()["detail"]

    r = client.get(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.json()["status"] == "error"


def test_test_server_unreachable(client, admin_token):
    sid = create_server(client, admin_token, "ns-down", port=1)
    r = client.post(f"/api/servers/{sid}/test", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_ssrf_rejected_private_network(client, admin_token):
    # Dev allowlist is 127.0.0.0/8 only -> private ranges are refused
    r = client.post("/api/servers", json=make_server_body("ns-ssrf", host="10.1.2.3"), headers=auth(admin_token))
    assert r.status_code == 422
    assert "not inside allowed management networks" in r.json()["detail"]


def test_ssrf_rejected_link_local(client, admin_token):
    r = client.post("/api/servers", json=make_server_body("ns-meta", host="169.254.169.254"), headers=auth(admin_token))
    assert r.status_code == 422
    assert "denied network" in r.json()["detail"]


def test_ssrf_rejected_loopback_via_hostname(client, admin_token):
    # localhost resolves to 127.0.0.1 which is allowed in dev; use a name
    # resolving outside the allowlist instead -> must be rejected
    r = client.post("/api/servers", json=make_server_body("ns-ext", host="example.com"), headers=auth(admin_token))
    assert r.status_code == 422


def test_weak_algorithm_rejected(client, admin_token):
    for weak in ("md5", "sha1", "sha224"):
        r = client.post("/api/servers", json=make_server_body(f"ns-{weak}", algorithm=weak), headers=auth(admin_token))
        assert r.status_code == 422, weak


def test_viewer_cannot_create_server(client, admin_token, mock_rndc):
    create_user(client, admin_token, "view1", role="viewer")
    token = login(client, "view1")
    r = client.post("/api/servers", json=make_server_body("ns-viewer"), headers=auth(token))
    assert r.status_code == 403


def test_operator_only_sees_assigned_servers(client, admin_token, mock_rndc):
    op_id = create_user(client, admin_token, "op1")
    sid_a = create_server(client, admin_token, "ns-a", port=mock_rndc.port)
    sid_b = create_server(client, admin_token, "ns-b", port=mock_rndc.port)

    # unassigned operator sees nothing
    token = login(client, "op1")
    r = client.get("/api/servers", headers=auth(token))
    assert r.status_code == 200
    assert r.json() == []

    # unassigned operator cannot test a server
    r = client.post(f"/api/servers/{sid_a}/test", headers=auth(token))
    assert r.status_code == 403

    # admin assigns op1 to ns-a only
    r = client.put(f"/api/servers/{sid_a}/assignments", json={"user_ids": [op_id]}, headers=auth(admin_token))
    assert r.status_code == 200, r.text

    r = client.get("/api/servers", headers=auth(token))
    names = [s["name"] for s in r.json()]
    assert names == ["ns-a"]

    r = client.get(f"/api/servers/{sid_a}", headers=auth(token))
    assert r.status_code == 200
    r = client.get(f"/api/servers/{sid_b}", headers=auth(token))
    assert r.status_code == 403

    # operator can test assigned server
    r = client.post(f"/api/servers/{sid_a}/test", headers=auth(token))
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # admin still sees both
    r = client.get("/api/servers", headers=auth(admin_token))
    assert len(r.json()) >= 2


def test_assignments_require_operator(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns-assign", port=mock_rndc.port)
    admin_id = client.get("/api/auth/me", headers=auth(admin_token)).json()["id"]
    r = client.put(f"/api/servers/{sid}/assignments", json={"user_ids": [admin_id]}, headers=auth(admin_token))
    assert r.status_code == 400  # admins cannot be assigned

    viewer_id = create_user(client, admin_token, "view2", role="viewer")
    r = client.put(f"/api/servers/{sid}/assignments", json={"user_ids": [viewer_id]}, headers=auth(admin_token))
    assert r.status_code == 400  # viewers cannot be assigned


def test_update_and_delete_server(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns5", port=mock_rndc.port)

    r = client.patch(f"/api/servers/{sid}", json={"notes": "updated"}, headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["notes"] == "updated"

    r = client.delete(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.status_code == 204
    r = client.get(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.status_code == 404


def test_audit_has_server_events(client, admin_token, mock_rndc):
    create_server(client, admin_token, "ns-audit", port=mock_rndc.port)
    r = client.get("/api/audit", headers=auth(admin_token))
    actions = [e["action"] for e in r.json()]
    assert "server.create" in actions