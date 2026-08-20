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


@pytest.fixture(scope="module")
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


def test_login_rate_limited_by_ip(client):
    # 5 failed attempts from the same IP (distinct unknown usernames so the
    # username key never trips) -> 6th attempt is blocked by the IP key.
    for i in range(5):
        r = client.post("/api/auth/login", json={"username": f"nosuch{i}", "password": "wrong"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": "nosuch5", "password": "wrong"})
    assert r.status_code == 429
    assert r.headers.get("retry-after") is not None


def test_successful_login_resets_rate_limit(client):
    for i in range(4):  # below the limit of 5
        r = client.post("/api/auth/login", json={"username": f"nosuch{i}", "password": "wrong"})
        assert r.status_code == 401

    # success clears the keys
    r = client.post("/api/auth/login", json={"username": "tadmin", "password": "Test_Admin_Pass_123!"})
    assert r.status_code == 200

    for i in range(5):  # fresh budget again
        r = client.post("/api/auth/login", json={"username": f"nosuch{i}", "password": "wrong"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": "nosuch5", "password": "wrong"})
    assert r.status_code == 429


def test_login_rate_limited_by_username(client):
    # Same username, 5 failures -> blocked even though the IP is "fresh".
    for i in range(5):
        r = client.post("/api/auth/login", json={"username": "victim", "password": "wrong"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": "victim", "password": "correct-guess"})
    assert r.status_code == 429