from typing import Optional
from sqlalchemy import Column, Float, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
import uuid
from datetime import datetime
from app.operations import add, subtract, multiply, divide
from app.models.base import Base  # Import shared Base
from sqlalchemy import DateTime

class Calculation(Base):
    __tablename__ = 'calculations'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    a = Column(Float, nullable=False)
    b = Column(Float, nullable=False)
    type = Column(String(50), nullable=False)  # e.g., 'add', 'subtract', 'multiply', 'divide'
    result = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Calculation(user_id={self.user_id}, type={self.type}, a={self.a}, b={self.b}, result={self.result})>"

    def perform_calculation(self) -> float:
        """Perform the calculation based on type using operations module and store result."""
        try:
            if self.type == 'add':
                self.result = add(self.a, self.b)
            elif self.type == 'subtract':
                self.result = subtract(self.a, self.b)
            elif self.type == 'multiply':
                self.result = multiply(self.a, self.b)
            elif self.type == 'divide':
                self.result = divide(self.a, self.b)
            else:
                raise ValueError(f"Invalid calculation type: {self.type}")
            return self.result
        except ValueError as e:
            raise e

    @classmethod
    def create_calculation(cls, db, user_id: uuid.UUID, a: float, b: float, calc_type: str) -> "Calculation":
        """Create and perform a new calculation."""
        try:
            # Validate user_id exists
            from .user import User  # Import here to avoid circular import
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise ValueError("Invalid user_id")

            # Create new calculation instance
            new_calculation = cls(
                user_id=user_id,
                a=a,
                b=b,
                type=calc_type
            )

            # Perform calculation
            new_calculation.perform_calculation()

            db.add(new_calculation)
            db.flush()
            return new_calculation

        except ValueError as e:
            raise e
