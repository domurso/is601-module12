import pytest
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import Base
from app.models.user import User
from app.models.calculations import Calculation
from datetime import datetime
from sqlalchemy import DateTime


# Create a test database engine (e.g., in-memory SQLite for testing)
engine = create_engine("sqlite:///:memory:", echo=False)
SessionLocal = sessionmaker(bind=engine)

@pytest.fixture
def db():
    # Create all tables
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Drop all tables after the test
        Base.metadata.drop_all(engine)

@pytest.fixture
def test_user(db):
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": "Password123"
    }
    user = User.register(db, user_data)
    db.commit()
    return user

def test_create_calculation(db, test_user):
    calc = Calculation.create_calculation(
        db=db,
        user_id=test_user.id,
        a=10.0,
        b=5.0,
        calc_type="add"
    )
    db.commit()
    assert calc.result == 15.0
    assert calc.user_id == test_user.id
    assert calc.type == "add"
