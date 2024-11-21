from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel,Field, validator
from typing import List, Annotated
from sqlalchemy.orm import Session
import medicals_models
from medicals_database import SessionLocal, engine
import logging
from medicals_models import  Base
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend URL
    allow_methods=["*"],
    allow_headers=["*"],
)

medicals_models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
dependency = Annotated[Session, Depends(get_db)]

class value(BaseModel):
    report_id:int=Field(..., description="The unique report ID, must be at least 3 digits and start with '1'.")
    patient_id:int
    center_id:int
    test_details:Optional[str] = None

    class Config:
        from_attributes = True  # Ensures that Pydantic can read from SQLAlchemy models



    @validator('report_id','patient_id','center_id')
    def validate_filed(cls,p):
        if p<=0:
            raise ValueError("Value must be positive")
        return p
    @validator('report_id')
    def validate_report_id(cls,r):
        if (len(str(r))>=3 and str(r)[0]=='1') :
            return r
            
            
        else:    
            raise ValueError("value must be greatest above 3 and also startwith only 1")


@app.post("/Medicals_val/",response_model=value)
def create_value(val:value,db: Session = Depends(get_db)):

    existing_item = db.query( medicals_models.MedicalReport).filter( medicals_models.MedicalReport.patient_id == val.patient_id).first()
    if existing_item:
        raise HTTPException(status_code=400, detail="patient_id already registered")
    else:

        db_val= medicals_models.MedicalReport(
            report_id=val.report_id,
            patient_id=val.patient_id,
            center_id=val.center_id,
            test_details=val.test_details if val.test_details else "val"
            

        )

        db.add(db_val)
        db.commit()
        db.refresh(db_val)  # Refresh to get the item with its auto-generated fields
        return db_val
        logging.info(f"Item saved: {db_val}")


#user authenatication
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
import jwt
from medicals_database import SessionLocal, engine, Base
from medicals_models import User
from fastapi import Query

# Initialize database
Base.metadata.create_all(bind=engine)

# FastAPI instance
app = FastAPI()

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "d2d2f3c6b8a1d5e3a61e1b8ed346b4b0d7688b3e5f3b687fb96a307178694b72"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1000000

# OAuth2PasswordBearer for extracting token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions for password hashing
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Create access token
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Get the current user from token
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# User schemas for validation
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

# Sign-up route
@app.post("/Sign_up", status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Check if username or email already exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password and create the user
    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, password_hash=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"msg": "User created successfully", "user_id": new_user.id}

# Sign-in route
@app.post("/signin")
def signin(user: UserLogin, db: Session = Depends(get_db)):
    # Check if the user exists
    existing_user = db.query(User).filter(User.username == user.username).first()
    
    if not existing_user:
        raise HTTPException(
            status_code=400, 
            detail="User not found. Please sign up first."
        )

    # Verify the password
    if not verify_password(user.password, existing_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Create JWT token
    access_token = create_access_token(data={"sub": existing_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route example
@app.get("/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "email": current_user.email}





