import pytest
from fastapi.testclient import TestClient
from app.asgi import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_token(client):
    response = client.post("/v1/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    data = response.json()
    return data.get("access_token", "")

def test_login_success(client):
    response = client.post("/v1/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_fail(client):
    response = client.post("/v1/auth/login", json={
        "username": "admin",
        "password": "wrong"
    })
    assert response.status_code == 401


def test_admin_without_auth(client):
    response = client.get("/v1/admin")
    assert response.status_code in (401, 403)

def test_admin_with_auth(client, admin_token):
    response = client.get(
        "/v1/admin",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["panel"] == "admin"


def test_health(client):
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json().get("data", {}).get("status") == "healthy"
