"""Pytest test fixtures."""

import pytest
from gateway.app import create_app


@pytest.fixture
def app():
    """Create test application instance."""
    app = create_app()
    app.config.update({"TESTING": True})
    return app


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()
