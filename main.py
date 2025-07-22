from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from typing import Optional
import uvicorn
import logging
from app.operations import add, subtract, multiply, divide
from app.models.user import User
from app.auth.dependencies import get_current_active_user, UserResponse
from app.database import SessionLocal  # Assume a database session factory

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
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    email: str = Field(..., max_length=120)
    username: str = Field(..., max_length=50)
    password: str = Field(..., min_length=6)

    @field_validator('email')
    def validate_email(cls, value):
        if '@' not in value:
            raise ValueError('Invalid email format')
        return value

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# Custom Exception Handlers (existing)
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

# User Endpoints
@app.post("/users/register", response_model=UserResponse, responses={400: {"model": ErrorResponse}})
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
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

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
