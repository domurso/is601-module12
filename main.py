from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError, ProgrammingError
from typing import Optional
import uuid
from datetime import datetime
import uvicorn
import logging
from app.operations import add, subtract, multiply, divide
from app.models.user import User
from app.models.calculations import Calculation
from app.auth.dependencies import get_current_active_user, UserResponse
from app.database import SessionLocal

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Setup templates directory
templates = Jinja2Templates(directory="templates")

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic model for request data (existing)
class OperationRequest(BaseModel):
    a: float = Field(..., description="The first number")
    b: float = Field(..., description="The second number")

    @field_validator('a', 'b')
    def validate_numbers(cls, value):
        if not isinstance(value, (int, float)):
            raise ValueError('Both a and b must be numbers.')
        return value

# Pydantic model for successful response (existing)
class OperationResponse(BaseModel):
    result: float = Field(..., description="The result of the operation")

# Pydantic model for error response (existing)
class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error message")

# Pydantic schemas for user
class UserCreate(BaseModel):
    first_name: str = Field(..., max_length=50, description="User's first name (max 50 characters)")
    last_name: str = Field(..., max_length=50, description="User's last name (max 50 characters)")
    email: str = Field(..., max_length=120, description="User's email address (max 120 characters)")
    username: str = Field(..., max_length=50, description="Unique username (max 50 characters)")
    password: str = Field(..., min_length=6, description="Password (minimum 6 characters)")

    @field_validator('email')
    def validate_email(cls, value):
        if '@' not in value:
            raise ValueError('Invalid email format')
        return value

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Token type, e.g., bearer")
    user: UserResponse = Field(..., description="User details")

# Pydantic schemas for calculation
class CalculationCreate(BaseModel):
    a: float = Field(..., description="The first number")
    b: float = Field(..., description="The second number")
    type: str = Field(..., description="Operation type: add, subtract, multiply, divide")

    @field_validator('type')
    def validate_type(cls, value):
        valid_types = ['add', 'subtract', 'multiply', 'divide']
        if value not in valid_types:
            raise ValueError(f"Type must be one of {valid_types}")
        return value

class CalculationRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    a: float
    b: float
    type: str
    result: Optional[float]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True  # Updated for SQLAlchemy 2.0 compatibility

# Custom Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTPException on {request.url.path}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_messages = "; ".join([f"{err['loc'][-1]}: {err['msg']}" for err in exc.errors()])
    logger.error(f"ValidationError on {request.url.path}: {error_messages}")
    return JSONResponse(
        status_code=400,
        content={"error": error_messages},
    )

@app.exception_handler(OperationalError)
async def operational_exception_handler(request: Request, exc: OperationalError):
    logger.error(f"Database OperationalError on {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Database connection error, please ensure the database is initialized"},
    )

@app.exception_handler(ProgrammingError)
async def programming_exception_handler(request: Request, exc: ProgrammingError):
    logger.error(f"Database ProgrammingError on {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Database table not found, please initialize the database"},
    )

# Existing Root Endpoint
@app.get("/")
async def read_root(request: Request):
    """
    Serve the index.html template.
    """
    return templates.TemplateResponse("index.html", {"request": request})

# Existing Operation Endpoints
@app.post("/add", response_model=OperationResponse, responses={400: {"model": ErrorResponse}})
async def add_route(operation: OperationRequest):
    """
    Add two numbers.
    """
    try:
        result = add(operation.a, operation.b)
        return OperationResponse(result=result)
    except Exception as e:
        logger.error(f"Add Operation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/subtract", response_model=OperationResponse, responses={400: {"model": ErrorResponse}})
async def subtract_route(operation: OperationRequest):
    """
    Subtract two numbers.
    """
    try:
        result = subtract(operation.a, operation.b)
        return OperationResponse(result=result)
    except Exception as e:
        logger.error(f"Subtract Operation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/multiply", response_model=OperationResponse, responses={400: {"model": ErrorResponse}})
async def multiply_route(operation: OperationRequest):
    """
    Multiply two numbers.
    """
    try:
        result = multiply(operation.a, operation.b)
        return OperationResponse(result=result)
    except Exception as e:
        logger.error(f"Multiply Operation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/divide", response_model=OperationResponse, responses={400: {"model": ErrorResponse}})
async def divide_route(operation: OperationRequest):
    """
    Divide two numbers.
    """
    try:
        result = divide(operation.a, operation.b)
        return OperationResponse(result=result)
    except ValueError as e:
        logger.error(f"Divide Operation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Divide Operation Internal Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Test Endpoint to Verify Swagger Rendering
@app.post("/test-register", response_model=UserCreate)
async def test_register(user_data: UserCreate):
    """
    Test endpoint to verify UserCreate schema rendering.
    """
    return user_data

# User Endpoints
@app.post("/users/register", response_model=UserResponse, responses={400: {"model": ErrorResponse}})
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with the provided details.

    Request Body:
    - **first_name**: User's first name (max 50 characters)
    - **last_name**: User's last name (max 50 characters)
    - **email**: User's email address (max 120 characters, must include '@')
    - **username**: Unique username (max 50 characters)
    - **password**: Password (minimum 6 characters)

    Returns:
    - User details on successful registration

    Raises:
    - 400: If username or email already exists or input is invalid
    """
    try:
        user = User.register(db, user_data.dict())
        db.commit()
        logger.info(f"User registered: {user.email}")
        return UserResponse.model_validate(user)
    except ValueError as e:
        logger.error(f"User Registration Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/users/login", response_model=Token, responses={401: {"model": ErrorResponse}})
async def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.

    Form Data:
    - **username**: Username or email
    - **password**: Password

    Returns:
    - JWT token and user details
    """
    token_data = User.authenticate(db, form_data.username, form_data.password)
    if not token_data:
        logger.error(f"Login failed for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info(f"User logged in: {form_data.username}")
    return token_data

# Calculation Endpoints (BREAD)
@app.get("/calculations", response_model=list[CalculationRead], responses={401: {"model": ErrorResponse}})
async def browse_calculations(
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    List all calculations for the authenticated user.

    Returns:
    - List of calculations associated with the user

    Raises:
    - 401: If user is not authenticated
    """
    calculations = db.query(Calculation).filter(Calculation.user_id == current_user.id).all()
    logger.info(f"User {current_user.email} browsed calculations")
    return calculations

@app.get("/calculations/{id}", response_model=CalculationRead, responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def read_calculation(
    id: uuid.UUID,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve a specific calculation by ID.

    Parameters:
    - **id**: UUID of the calculation

    Returns:
    - Calculation details

    Raises:
    - 401: If user is not authenticated
    - 404: If calculation is not found or doesn't belong to the user
    """
    calculation = db.query(Calculation).filter(
        Calculation.id == id,
        Calculation.user_id == current_user.id
    ).first()
    if not calculation:
        logger.error(f"Calculation {id} not found for user {current_user.email}")
        raise HTTPException(status_code=404, detail="Calculation not found")
    logger.info(f"User {current_user.email} retrieved calculation {id}")
    return calculation

@app.put("/calculations/{id}", response_model=CalculationRead, responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def edit_calculation(
    id: uuid.UUID,
    calc_data: CalculationCreate,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Update a calculation by ID.

    Parameters:
    - **id**: UUID of the calculation
    - **calc_data**: JSON body with updated calculation details
        - **a**: First number
        - **b**: Second number
        - **type**: Operation type (add, subtract, multiply, divide)

    Returns:
    - Updated calculation details

    Raises:
    - 400: If input is invalid (e.g., invalid operation type)
    - 401: If user is not authenticated
    - 404: If calculation is not found or doesn't belong to the user
    """
    calculation = db.query(Calculation).filter(
        Calculation.id == id,
        Calculation.user_id == current_user.id
    ).first()
    if not calculation:
        logger.error(f"Calculation {id} not found for user {current_user.email}")
        raise HTTPException(status_code=404, detail="Calculation not found")
    
    calculation.a = calc_data.a
    calculation.b = calc_data.b
    calculation.type = calc_data.type
    try:
        calculation.perform_calculation()
        db.commit()
        db.refresh(calculation)
        logger.info(f"User {current_user.email} updated calculation {id}")
        return calculation
    except ValueError as e:
        logger.error(f"Calculation Update Error for {id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/calculations", response_model=CalculationRead, responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}})
async def add_calculation(
    calc_data: CalculationCreate,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Create a new calculation.

    Request Body:
    - **a**: First number
    - **b**: Second number
    - **type**: Operation type (add, subtract, multiply, divide)

    Returns:
    - Created calculation details

    Raises:
    - 400: If input is invalid (e.g., invalid operation type)
    - 401: If user is not authenticated
    """
    try:
        calculation = Calculation.create_calculation(
            db=db,
            user_id=current_user.id,
            a=calc_data.a,
            b=calc_data.b,
            calc_type=calc_data.type
        )
        db.commit()
        db.refresh(calculation)
        logger.info(f"User {current_user.email} created calculation {calculation.id}")
        return calculation
    except ValueError as e:
        logger.error(f"Calculation Creation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/calculations/{id}", status_code=status.HTTP_204_NO_CONTENT, responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
async def delete_calculation(
    id: uuid.UUID,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Delete a calculation by ID.

    Parameters:
    - **id**: UUID of the calculation

    Raises:
    - 401: If user is not authenticated
    - 404: If calculation is not found or doesn't belong to the user
    """
    calculation = db.query(Calculation).filter(
        Calculation.id == id,
        Calculation.user_id == current_user.id
    ).first()
    if not calculation:
        logger.error(f"Calculation {id} not found for user {current_user.email}")
        raise HTTPException(status_code=404, detail="Calculation not found")
    
    db.delete(calculation)
    db.commit()
    logger.info(f"User {current_user.email} deleted calculation {id}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
