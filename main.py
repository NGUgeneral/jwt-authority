import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from mangum import Mangum

# --- CONFIGURATION & ENVIRONMENT ---
class Settings(BaseSettings):
    DATABASE_URL: str
    TOKEN_ISSUER_SECRET: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_DAYS: int = 1
    REFRESH_TOKEN_EXPIRE_DAYS: int = 365

    class Config:
        env_file = ".env"

settings = Settings()

# --- DATABASE SETUP ---
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuthSession(Base):
    __tablename__ = "jwt_auth_sessions"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    token_hash = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- UTILS & CRYPTO ---
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def generate_opaque_token() -> str:
    return os.urandom(32).hex()

def create_access_token() -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode = {"exp": expire, "type": "access"}
    import jwt
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

# --- API SCHEMAS ---
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

v1_router = APIRouter(prefix="/api/v1")
secret_header = APIKeyHeader(name="X-Instance-Secret", auto_error=True)

@v1_router.post("/auth/token", response_model=TokenResponse)
def issue_tokens(secret: str = Depends(secret_header), db: Session = Depends(get_db)):
    """Initial exchange: Verifies instance secret and issues the initial token pair."""
    if secret != settings.TOKEN_ISSUER_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token issuer secret"
        )
    
    # 1. Generate short-lived Access Token (JWT)
    access_token = create_access_token()
    
    # 2. Generate long-lived Refresh Token (Opaque)
    raw_refresh_token = generate_opaque_token()
    refresh_hash = hash_token(raw_refresh_token)
    
    # 3. Save hashed refresh token to Supabase
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db_session = AuthSession(token_hash=refresh_hash, expires_at=expires_at)
    db.add(db_session)
    db.commit()
    
    return {"access_token": access_token, "refresh_token": raw_refresh_token}


@v1_router.post("/auth/refresh", response_model=TokenResponse)
def refresh_access_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    """Rotation/Refresh: Validates opaque refresh token and provides rotating pairs."""
    incoming_hash = hash_token(payload.refresh_token)
    
    # Look up the session in Supabase
    db_session = db.query(AuthSession).filter(AuthSession.token_hash == incoming_hash).first()
    
    if not db_session:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
        
    if db_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(db_session)
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    # Generate new pair
    new_access_token = create_access_token()
    new_raw_refresh_token = generate_opaque_token()
    new_refresh_hash = hash_token(new_raw_refresh_token)
    
    # Update database record (Token Rotation strategy)
    db_session.token_hash = new_refresh_hash
    db_session.expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db.commit()
    
    return {"access_token": new_access_token, "refresh_token": new_raw_refresh_token}


@v1_router.post("/auth/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    """Explicitly deletes a session row, immediately invalidating the refresh capabilities."""
    incoming_hash = hash_token(payload.refresh_token)
    db_session = db.query(AuthSession).filter(AuthSession.token_hash == incoming_hash).first()
    
    if db_session:
        db.delete(db_session)
        db.commit()
    return

# --- MAIN FASTAPI APPLICATION ---
app = FastAPI(
    title="JWT Authority Service",
    description="Handles token generation, validation, and session rotation via AWS Lambda."
)

# Register the versioned router
app.include_router(v1_router)

# --- AWS LAMBDA HANDLER ---
handler = Mangum(app)