import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DATABASE_URL"] = "sqlite:///./test_secure_dns.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_PASSWORD"] = "Test_Admin_Pass_123!"
os.environ["ADMIN_USERNAME"] = "tadmin"

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


def make_server_body(name: str, port: int = 953, secret: str = TEST_SECRET_B64) -> dict:
    return {
        "name": name,
        "host": "127.0.0.1",
        "notes": "test server",
        "rndc_port": port,
        "rndc_key_name": "rndc-key",
        "rndc_algorithm": "sha256",
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


def test_create_server(client, admin_token, mock_rndc):
    sid = create_server(client, admin_token, "ns1", port=mock_rndc.port)
    r = client.get(f"/api/servers/{sid}", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["name"] == "ns1"
    assert r.json()["status"] == "unknown"


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


def test_viewer_cannot_create_server(client, admin_token, mock_rndc):
    client.post(
        "/api/users",
        json={"username": "view1", "email": "view1@example.com", "password": "Viewer_Pass_123!", "role": "viewer"},
        headers=auth(admin_token),
    )
    login = client.post("/api/auth/login", json={"username": "view1", "password": "Viewer_Pass_123!"})
    viewer_token = login.json()["access_token"]
    r = client.post("/api/servers", json=make_server_body("ns-viewer"), headers=auth(viewer_token))
    assert r.status_code == 403


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