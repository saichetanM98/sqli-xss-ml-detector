"""Test for Gateway health check route."""

import pytest
from gateway.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "adaptive-security-gateway"
    assert "cuda_available" in data
    assert "database" in data
    assert data["vocab_loaded"] is True
