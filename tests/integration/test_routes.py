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
import uuid
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Override get_db and get_current_user dependencies
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

# User Endpoint Tests
@pytest.mark.asyncio
async def test_register_user(client: TestClient, db_session: Session, fake_user_data):
    response = client.post("/users/register", json=fake_user_data)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == fake_user_data["email"]
    assert data["username"] == fake_user_data["username"]
    assert data["is_active"] is True
    
    # Verify in DB
    user = db_session.query(User).filter(User.email == fake_user_data["email"]).first()
    assert user is not None
    assert user.username == fake_user_data["username"]
    logger.info(f"Registered user: {fake_user_data['email']}")

@pytest.mark.asyncio
async def test_register_duplicate_email(client: TestClient, db_session: Session, fake_user_data):
    client.post("/users/register", json=fake_user_data)
    duplicate_data = {**fake_user_data, "username": f"{fake_user_data['username']}2"}
    response = client.post("/users/register", json=duplicate_data)
    assert response.status_code == 400
    assert response.json() == {"error": "Username or email already exists"}
    logger.info("Tested duplicate email registration")

@pytest.mark.asyncio
async def test_login_user(client: TestClient, db_session: Session, test_user: User, fake_user_data):
    response = client.post(
        "/users/login",
        data={"username": test_user.username, "password": fake_user_data["password"]}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data
    assert data["user"]["email"] == test_user.email
    
    # Verify last_login updated in DB
    db_session.refresh(test_user)
    assert test_user.last_login is not None
    logger.info(f"Logged in user: {test_user.email}")

@pytest.mark.asyncio
async def test_login_invalid_credentials(client: TestClient, test_user: User):
    response = client.post(
        "/users/login",
        data={"username": test_user.username, "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Incorrect username or password"}
    logger.info("Tested invalid login credentials")

@pytest.mark.asyncio
async def test_get_users(client: TestClient, db_session: Session, test_user: User):
    response = client.get("/users")
    assert response.status_code == 200
    data = response.json()
    assert any(user["email"] == test_user.email for user in data)
    
    # Verify in DB
    users = db_session.query(User).all()
    assert any(user.email == test_user.email for user in users)
    logger.info("Tested get users endpoint")

# Calculation Endpoint Tests
@pytest.mark.asyncio
async def test_create_calculation(client: TestClient, test_token: str, db_session: Session, test_user: User):
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
    calc = db_session.query(Calculation).filter(Calculation.id == uuid.UUID(data["id"])).first()
    assert calc is not None
    assert calc.user_id == test_user.id
    logger.info("Created calculation")

@pytest.mark.asyncio
async def test_create_calculation_invalid_type(client: TestClient, test_token: str):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "invalid"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 422
    assert any("Type must be one of ['add', 'subtract', 'multiply', 'divide']" in error["msg"] for error in response.json()["detail"])
    logger.info("Tested invalid calculation type")

@pytest.mark.asyncio
async def test_create_calculation_unauthorized(client: TestClient):
    response = client.post(
        "/calculations",
        json={"a": 10, "b": 5, "type": "add"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "Could not validate credentials"}
    logger.info("Tested unauthorized calculation creation")

@pytest.mark.asyncio
async def test_get_calculations(client: TestClient, test_token: str, db_session: Session, test_user: User):
    calc = Calculation.create_calculation(db=db_session, user_id=test_user.id, a=10, b=5, calc_type="add")
    db_session.commit()
    
    response = client.get("/calculations", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["a"] == 10
    assert data[0]["result"] == 15
    
    # Verify in DB
    calcs = db_session.query(Calculation).filter(Calculation.user_id == test_user.id).all()
    assert len(calcs) == 1
    logger.info("Tested get calculations")

@pytest.mark.asyncio
async def test_get_calculation(client: TestClient, test_token: str, db_session: Session, test_user: User):
    calc = Calculation.create_calculation(db=db_session, user_id=test_user.id, a=20, b=4, calc_type="multiply")
    db_session.commit()
    
    response = client.get(f"/calculations/{calc.id}", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(calc.id)
    assert data["a"] == 20
    assert data["result"] == 80
    
    # Verify in DB
    calc_db = db_session.query(Calculation).filter(Calculation.id == calc.id).first()
    assert calc_db is not None
    logger.info("Tested get calculation by ID")

@pytest.mark.asyncio
async def test_get_calculation_not_found(client: TestClient, test_token: str):
    response = client.get(f"/calculations/{uuid.uuid4()}", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Tested get calculation not found")

@pytest.mark.asyncio
async def test_update_calculation(client: TestClient, test_token: str, db_session: Session, test_user: User):
    calc = Calculation.create_calculation(db=db_session, user_id=test_user.id, a=10, b=5, calc_type="add")
    db_session.commit()
    
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
    
    # Verify in DB
    calc_db = db_session.query(Calculation).filter(Calculation.id == calc.id).first()
    assert calc_db.a == 20
    assert calc_db.result == 80
    logger.info("Tested update calculation")

@pytest.mark.asyncio
async def test_update_calculation_not_found(client: TestClient, test_token: str):
    response = client.put(
        f"/calculations/{uuid.uuid4()}",
        json={"a": 20, "b": 4, "type": "multiply"},
        headers={"Authorization": f"Bearer {test_token}"}
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Tested update calculation not found")

@pytest.mark.asyncio
async def test_delete_calculation(client: TestClient, test_token: str, db_session: Session, test_user: User):
    calc = Calculation.create_calculation(db=db_session, user_id=test_user.id, a=10, b=5, calc_type="add")
    db_session.commit()
    
    response = client.delete(f"/calculations/{calc.id}", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 204
    
    # Verify in DB
    calc_db = db_session.query(Calculation).filter(Calculation.id == calc.id).first()
    assert calc_db is None
    logger.info("Tested delete calculation")

@pytest.mark.asyncio
async def test_delete_calculation_not_found(client: TestClient, test_token: str):
    response = client.delete(f"/calculations/{uuid.uuid4()}", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 404
    assert response.json() == {"error": "Calculation not found"}
    logger.info("Tested delete calculation not found")
