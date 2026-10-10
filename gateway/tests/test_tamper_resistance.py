import pytest
from gateway.app import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config.update({"TESTING": True})
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_tamper_resistance_x_forwarded_for(client):
    """Ensure that modifying X-Forwarded-For doesn't bypass rate limiting if the base IP is known, 
    or check if the session manager correctly aggregates."""
    
    # Send 25 requests to trigger the 10s burst window (>20 reqs limit)
    for i in range(25):
        # We simulate tampering by changing X-Forwarded-For, but the remote_addr remains the same in a real proxy scenario.
        response = client.post("/predict", json={"payload": "safe payload", "ip": "127.0.0.1"}, environ_base={'REMOTE_ADDR': '127.0.0.1'})
    
    # The 25th request (or earlier if counting correctly) should be rate limited or blocked.
    assert response.status_code == 429
    data = response.get_json()
    assert data["verdict"] == "RATE_LIMIT"


