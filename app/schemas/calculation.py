# app/schemas/calculation.py
from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from enum import Enum

class CalculationType(str, Enum):
    """Enum for valid calculation types"""
    ADD = "add"
    SUBTRACT = "subtract"
    MULTIPLY = "multiply"
    DIVIDE = "divide"

class CalculationCreate(BaseModel):
    """Schema for creating a calculation"""
    a: float = Field(..., description="First number for the calculation")
    b: float = Field(..., description="Second number for the calculation")
    type: CalculationType = Field(..., description="Type of calculation to perform")

    @field_validator("b")
    def prevent_zero_divisor(cls, v, info):
        """Ensure b is not zero when type is divide"""
        if info.data.get("type") == CalculationType.DIVIDE and v == 0:
            raise ValueError("Cannot divide by zero")
        return v

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "a": 10.0,
                "b": 5.0,
                "type": "add"
            }
        }
    )

class CalculationRead(BaseModel):
    """Schema for reading calculation data"""
    id: UUID
    user_id: UUID
    a: float
    b: float
    type: CalculationType
    result: Optional[float] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "user_id": "987fcdeb-12d3-4e5f-6789-426614174000",
                "a": 10.0,
                "b": 5.0,
                "type": "add",
                "result": 15.0,
                "created_at": "2025-01-01T00:00:00",
                "updated_at": "2025-01-01T00:00:00"
            }
        }
    )
