import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from fastapi import status
from main import app, get_db
from app.models.user import User
from app.models.calculations import Calculation
from app.schemas.user import UserResponse
from app.auth.dependencies import get_current_user
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Override dependencies
def override_get_db(db_session: Session):
    def _get_db():
        yield db_session
    return _get_db

def override_get_current_user(db_session: Session):
    def _get_current_user(token: str):
        user_id = User.verify_token(token)
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db_session.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return UserResponse.model_validate(user)
    return _get_current_user

@pytest_asyncio.fixture
async def client(db_session: Session):
    app.dependency_overrides[get_db] = override_get_db(db_session)
    app.dependency_overrides[get_current_user] = override_get_current_user(db_session)
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest_asyncio.fixture
async def test_user(db_session: Session, fake_user_data):
    user_data = fake_user_data
    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)
    logger.info(f"Created test user: {user.email}")
    return user

@pytest_asyncio.fixture
async def test_token(test_user: User):
    token = User.create_access_token({"sub": str(test_user.id)})
    return token

# User Tests
@pytest.mark.asyncio
async def test_register_user(client: TestClient, db_session: Session, fake_user_data):
    """
    Test the user registration endpoint.
    Sends a POST request to /users/register and verifies user data in DB.
    """
    response = client.post("/users/register", json=fake_user_data)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == fake_user_data["email"]
    assert data["username"] == fake_user_data["username"]
    
    # Verify in DB
    user = db_session.query(User).filter(User.email == fake_user_data["email"]).first()
    assert user is not None
    assert user.username == fake_user_data["username"]
    logger.info(f"Registered user: {fake_user_data['email']}")

@pytest.mark.asyncio
async def test_login_user(client: TestClient, db_session: Session, test_user: User, fake_user_data):
    """
    Test the user login endpoint.
    Sends a POST request to /users/login and verifies last_login in DB.
    """
    response = client.post(
        "/users/login",
        data={"username": test_user.username, "password": fake_user_data["password"]}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == test_user.email
    
    # Verify last_login in DB
    db_session.refresh(test_user)
    assert test_user.last_login is not None
    logger.info(f"Logged in user: {test_user.email}")

# Calculation Tests
@pytest.mark.asyncio
async def test_create_calculation(client: TestClient, test_token: str, db_session: Session, test_user: User):
    """
    Test the calculation creation endpoint.
    Sends a POST request to /calculations and verifies data in DB.
    """
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "add"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["a"] == 10
    assert data["b"] == 5
    assert data["type"] == "add"
    assert data["result"] == 15
    
    # Verify in DB
    calc = db_session.query(Calculation).filter(Calculation.user_id == test_user.id).first()
    assert calc is not None
    assert calc.a == 10
    assert calc.result == 15
    logger.info("Created calculation")

@pytest.mark.asyncio
async def test_create_calculation_invalid_type(client: TestClient, test_token: str):
    """
    Test the calculation creation endpoint with invalid type.
    Sends a POST request to /calculations with invalid type and verifies error.
    """
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "invalid"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 422
