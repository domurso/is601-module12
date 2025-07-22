import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from fastapi import status
from main import app, get_db  # Import from root directory
from app.models.user import User
from app.models.calculations import Calculation
import uuid
from datetime import datetime
from app.auth.dependencies import UserResponse

# Override the get_db dependency for testing
def override_get_db(db_session: Session):
    def _get_db():
        try:
            yield db_session
        finally:
            pass  # db_session is managed by conftest.py
    return _get_db

@pytest_asyncio.fixture
async def client(db_session: Session):
    app.dependency_overrides[get_db] = override_get_db(db_session)
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest_asyncio.fixture
async def test_user(db_session: Session, create_fake_user):
    user_data = create_fake_user
    user_data["password"] = User.hash_password(user_data["password"])
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    logger.info(f"Created test user: {user.email}")
    return user

@pytest_asyncio.fixture
async def test_token(test_user: User):
    token_data = {"sub": str(test_user.id)}
    token = User.create_access_token(token_data)
    return token

@pytest.mark.asyncio
async def test_register_user(client: TestClient, create_fake_user):
    user_data = create_fake_user
    response = client.post(
        "/users/register",
        json=user_data
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["username"] == user_data["username"]
    assert data["is_active"] is True
    assert data["is_verified"] is False
    logger.info(f"Successfully tested user registration: {user_data['email']}")

@pytest.mark.asyncio
async def test_register_user_duplicate_email(client: TestClient, create_fake_user):
    # Register first user
    user_data = create_fake_user
    client.post("/users/register", json=user_data)
    
    # Try registering with same email
    duplicate_data = create_fake_user
    duplicate_data["email"] = user_data["email"]  # Force duplicate email
    duplicate_data["username"] = f"{duplicate_data['username']}2"
    response = client.post("/users/register", json=duplicate_data)
    assert response.status_code == 400
    assert response.json() == {"error": "Username or email already exists"}
    logger.info("Successfully tested duplicate email registration")

@pytest.mark.asyncio
async def test_login_user(client: TestClient, test_user: User):
    response = client.post(
        "/users/login",
        data={"username": test_user.username, "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data
    assert data["user"]["email"] == test_user.email
    logger.info(f"Successfully tested login for user: {test_user.email}")

@pytest.mark.asyncio
async def test_login_invalid_credentials(client: TestClient, test_user: User):
    response = client.post(
        "/users/login",
        data={"username": test_user.username, "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Incorrect username or password"}
    logger.info("Successfully tested invalid login credentials")

@pytest.mark.asyncio
async def test_get_users(client: TestClient, test_user: User):
    response = client.get("/users")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert any(user["email"] == test_user.email for user in data)
    logger.info("Successfully tested get users endpoint")

@pytest.mark.asyncio
async def test_add_calculation(client: TestClient, test_token: str, test_db: Session):
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
    assert "id" in data
    assert "user_id" in data
    logger.info("Successfully tested add calculation")

@pytest.mark.asyncio
async def test_add_calculation_unauthorized(client: TestClient):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "add"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Could not validate credentials"}
    logger.info("Successfully tested unauthorized add calculation")

@pytest.mark.asyncio
async def test_add_calculation_invalid_type(client: TestClient, test_token: str):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "invalid"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "Invalid calculation type: invalid"}
    logger.info("Successfully tested invalid calculation type")

@pytest.mark.asyncio
async def test_browse_calculations(client: TestClient, test_token: str, test_db: Session, test_user: User):
    # Add a calculation
    calc = Calculation(
        user_id=test_user.id,
        a=10,
        b=5,
        type="add",
        result=15,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(calc)
    test_db.commit()
    
    response = client.get(
        "/calculations",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["a"] == 10
    assert data[0]["result"] == 15
    logger.info("Successfully tested browse calculations")

@pytest.mark.asyncio
async def test_read_calculation(client: TestClient, test_token: str, test_db: Session, test_user: User):
    # Add a calculation
    calc = Calculation(
        id=uuid.uuid4(),
        user_id=test_user.id,
        a=20,
        b=4,
        type="multiply",
        result=80,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(calc)
    test_db.commit()
    
    response = client.get(
        f"/calculations/{calc.id}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(calc.id)
    assert data["a"] == 20
    assert data["result"] == 80
    logger.info("Successfully tested read calculation")

@pytest.mark.asyncio
async def test_read_calculation_not_found(client: TestClient, test_token: str):
    response = client.get(
        f"/calculations/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Successfully tested read calculation not found")

@pytest.mark.asyncio
async def test_update_calculation(client: TestClient, test_token: str, test_db: Session, test_user: User):
    # Add a calculation
    calc = Calculation(
        id=uuid.uuid4(),
        user_id=test_user.id,
        a=10,
        b=5,
        type="add",
        result=15,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(calc)
    test_db.commit()
    
    response = client.put(
        f"/calculations/{calc.id}",
        json={"a": 20, "b": 4, "type": "multiply"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["a"] == 20
    assert data["b"] == 4
    assert data["type"] == "multiply"
    assert data["result"] == 80
    logger.info("Successfully tested update calculation")

@pytest.mark.asyncio
async def test_update_calculation_not_found(client: TestClient, test_token: str):
    response = client.put(
        f"/calculations/{uuid.uuid4()}",
        json={"a": 20, "b": 4, "type": "multiply"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Successfully tested update calculation not found")

@pytest.mark.asyncio
async def test_delete_calculation(client: TestClient, test_token: str, test_db: Session, test_user: User):
    # Add a calculation
    calc = Calculation(
        id=uuid.uuid4(),
        user_id=test_user.id,
        a=10,
        b=5,
        type="add",
        result=15,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(calc)
    test_db.commit()
    
    response = client.delete(
        f"/calculations/{calc.id}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 204
    
    # Verify deletion
    calc = test_db.query(Calculation).filter(Calculation.id == calc.id).first()
    assert calc is None
    logger.info("Successfully tested delete calculation")

@pytest.mark.asyncio
async def test_delete_calculation_not_found(client: TestClient, test_token: str):
    response = client.delete(
        f"/calculations/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Successfully tested delete calculation not found")
