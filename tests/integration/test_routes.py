import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from main import app, get_db  # Import from root main.py
from tests.conftest import db_session, create_fake_user, test_user
from app.models.user import User
import logging

logger = logging.getLogger(__name__)

@pytest.fixture
def client(db_session):
    """
    Provide a TestClient with get_db overridden to use db_session from conftest.py.
    """
    def override_get_db():
        yield db_session  # Use the test database session
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()  # Clean up after tests

def test_get_users(client, db_session):
    """
    Test the /users endpoint with a single user.
    """
    # Add test data
    user_data = create_fake_user()
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    logger.info(f"Added test user: {user.email}")

    # Test the endpoint
    response = client.get("/users")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["email"] == user_data["email"]
    logger.info("Successfully tested /users endpoint")

def test_get_users_with_test_user(client, test_user):
    """
    Test the /users endpoint using the test_user fixture.
    """
    response = client.get("/users")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["email"] == test_user.email
    logger.info("Successfully tested /users endpoint with test_user")

def test_get_users_empty(client):
    """
    Test the /users endpoint with an empty database.
    """
    response = client.get("/users")
    assert response.status_code == 200
    assert response.json() == []
    logger.info("Successfully tested /users endpoint with empty database")
