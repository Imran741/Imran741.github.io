"""Integration tests for the /api/analyze endpoint (breach check disabled)."""

import pytest

from app import create_app
from config import TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client


def _analyze(client, payload):
    return client.post("/api/analyze", json=payload)


def test_dashboard_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Password Security Analyzer" in response.data


def test_analyze_returns_full_report(client):
    response = _analyze(client, {"password": "X7#mQ9$vL2@k", "check_breach": False})
    assert response.status_code == 200
    data = response.get_json()
    assert set(data) == {
        "length", "score", "entropy", "crack_time", "patterns", "breach", "recommendations",
    }
    assert data["length"] == 12
    assert 0 <= data["score"]["score"] <= 100
    # Password must never be echoed back.
    assert "X7#mQ9$vL2@k" not in response.get_data(as_text=True)


def test_missing_password_rejected(client):
    assert _analyze(client, {}).status_code == 400


def test_empty_password_rejected(client):
    assert _analyze(client, {"password": ""}).status_code == 400


def test_non_string_password_rejected(client):
    assert _analyze(client, {"password": 12345}).status_code == 400


def test_overlong_password_rejected(client):
    response = _analyze(client, {"password": "a" * 500, "check_breach": False})
    assert response.status_code == 400


def test_non_json_body_rejected(client):
    response = client.post("/api/analyze", data="password=abc")
    assert response.status_code in (400, 415)


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
