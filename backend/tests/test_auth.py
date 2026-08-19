import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DATABASE_URL"] = "sqlite:///./test_secure_dns.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_PASSWORD"] = "Test_Admin_Pass_123!"
os.environ["ADMIN_USERNAME"] = "tadmin"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token(client):
    resp = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_success(client):
    r = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_login_bad_password(client):
    r = client.post("/api/auth/login", json={"username": "tadmin", "password": "wrong-password"})
    assert r.status_code == 401


def test_me(client, admin_token):
    r = client.get("/api/auth/me", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["username"] == "tadmin"
    assert r.json()["role"] == "admin"


def test_me_no_token(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_refresh_flow(client, admin_token):
    login = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    refresh = login.json()["refresh_token"]
    r = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_refresh_reuse_revoked(client):
    login = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    refresh = login.json()["refresh_token"]
    r1 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r1.status_code == 200
    r2 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 401


def test_admin_creates_user(client, admin_token):
    r = client.post(
        "/api/users",
        json={"username": "op1", "email": "op1@example.com", "password": "Operator_Pass_123!", "role": "operator"},
        headers=auth(admin_token),
    )
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "operator"


def test_viewer_cannot_create_user(client, admin_token):
    client.post(
        "/api/users",
        json={"username": "view1", "email": "view1@example.com", "password": "Viewer_Pass_123!", "role": "viewer"},
        headers=auth(admin_token),
    )
    login = client.post("/api/auth/login", json={"username": "view1", "password": "Viewer_Pass_123!"})
    viewer_token = login.json()["access_token"]

    r = client.post(
        "/api/users",
        json={"username": "hacker", "email": "h@example.com", "password": "Hacker_Pass_123!", "role": "admin"},
        headers=auth(viewer_token),
    )
    assert r.status_code == 403


def test_audit_log_has_login_events(client, admin_token):
    r = client.get("/api/audit", headers=auth(admin_token))
    assert r.status_code == 200
    actions = [e["action"] for e in r.json()]
    assert "auth.login" in actions