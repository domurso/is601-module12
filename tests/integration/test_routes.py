import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from fastapi import status
from app.main import app
from app.models.user import User
from app.models.calculation import Calculation
from app.database import SessionLocal
import uuid
from datetime import datetime
from jose import jwt
from app.auth.dependencies import UserResponse

# Use in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Override the get_db dependency for testing
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[app.get_db] = override_get_db

@pytest_asyncio.fixture
async def client():
    # Create tables
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    # Drop tables after tests
    Base.metadata.drop_all(bind=engine)

@pytest_asyncio.fixture
async def test_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest_asyncio.fixture
async def test_user(test_db: Session):
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": User.hash_password("securepassword123")
    }
    user = User(**user_data)
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user

@pytest_asyncio.fixture
async def test_token(test_user: User):
    token_data = {"sub": str(test_user.id)}
    token = User.create_access_token(token_data)
    return token

@pytest.mark.asyncio
async def test_register_user(client: TestClient):
    response = client.post(
        "/users/register",
        json={
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "username": "johndoe",
            "password": "securepassword123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "john@example.com"
    assert data["username"] == "johndoe"
    assert data["is_active"] is True
    assert data["is_verified"] is False

@pytest.mark.asyncio
async def test_register_user_duplicate_email(client: TestClient):
    # Register first user
    client.post(
        "/users/register",
        json={
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "username": "johndoe",
            "password": "securepassword123"
        }
    )
    # Try registering with same email
    response = client.post(
        "/users/register",
        json={
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "john@example.com",
            "username": "janedoe",
            "password": "securepassword123"
        }
    )
    assert response.status_code == 400
    assert response.json() == {"error": "Username or email already exists"}

@pytest.mark.asyncio
async def test_login_user(client: TestClient, test_user: User):
    response = client.post(
        "/users/login",
        data={"username": "testuser", "password": "securepassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data
    assert data["user"]["email"] == "test@example.com"

@pytest.mark.asyncio
async def test_login_invalid_credentials(client: TestClient, test_user: User):
    response = client.post(
        "/users/login",
        data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Incorrect username or password"}

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

@pytest.mark.asyncio
async def test_add_calculation_unauthorized(client: TestClient):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "add"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Could not validate credentials"}

@pytest.mark.asyncio
async def test_add_calculation_invalid_type(client: TestClient, test_token: str):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "invalid"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "Invalid calculation type: invalid"}

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

@pytest.mark.asyncio
async def test_read_calculation_not_found(client: TestClient, test_token: str):
    response = client.get(
        f"/calculations/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}

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

@pytest.mark.asyncio
async def test_update_calculation_not_found(client: TestClient, test_token: str):
    response = client.put(
        f"/calculations/{uuid.uuid4()}",
        json={"a": 20, "b": 4, "type": "multiply"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}

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

@pytest.mark.asyncio
async def test_delete_calculation_not_found(client: TestClient, test_token: str):
    response = client.delete(
        f"/calculations/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}

@pytest.mark.asyncio
async def test_operation_add(client: TestClient):
    response = client.post(
        "/add",
        json={"a": 10, "b": 5}
    )
    assert response.status_code == 200
    assert response.json() == {"result": 15}

@pytest.mark.asyncio
async def test_operation_subtract(client: TestClient):
    response = client.post(
        "/subtract",
        json={"a": 10, "b": 5}
    )
    assert response.status_code == 200
    assert response.json() == {"result": 5}

@pytest.mark.asyncio
async def test_operation_multiply(client: TestClient):
    response = client.post(
        "/multiply",
        json={"a": 10, "b": 5}
    )
    assert response.status_code == 200
    assert response.json() == {"result": 50}

@pytest.mark.asyncio
async def test_operation_divide(client: TestClient):
    response = client.post(
        "/divide",
        json={"a": 10, "b": 5}
    )
    assert response.status_code == 200
    assert response.json() == {"result": 2.0}

@pytest.mark.asyncio
async def test_operation_divide_by_zero(client: TestClient):
    response = client.post(
        "/divide",
        json={"a": 10, "b": 0}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "Cannot divide by zero!"}
