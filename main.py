import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, Column, String, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Literal, Optional
from mangum import Mangum

# --- CONFIGURATION & ENVIRONMENT ---
class Settings(BaseSettings):
    APP_ENV: Literal["local", "production"] = "production"
    DATABASE_URL: str
    TOKEN_ISSUER_SECRET: str
    JWT_SECRET_KEY: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_DAYS: int = 1
    REFRESH_TOKEN_EXPIRE_DAYS: int = 365
    TARGET_AWS_REGION: str = "eu-west-1"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()

# --- CENTRALIZED SECRET INJECTOR (COLD START) ---
def resolve_jwt_secret() -> str:
    """Conditionally retrieves the encryption secret based on the environment."""
    if settings.APP_ENV == "local":
        if not settings.JWT_SECRET_KEY:
            raise RuntimeError("CRITICAL: JWT_SECRET_KEY must be defined in your local .env file.")
        return settings.JWT_SECRET_KEY

    import boto3
    try:
        ssm_client = boto3.client('ssm', region_name=settings.TARGET_AWS_REGION)
        response = ssm_client.get_parameter(
            Name='/flagship/prod/jwt-secret',
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except Exception as e:
        raise RuntimeError(f"CRITICAL: Failed to load production secret from SSM: {str(e)}")

LIVE_JWT_SECRET = resolve_jwt_secret()

# --- DATABASE SETUP ---
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuthSession(Base):
    __tablename__ = "jwt_auth_sessions"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    token_hash = Column(String, unique=True, index=True, nullable=False)
    audience = Column(String, nullable=False)
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

def create_access_token(audience: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode = {
        "exp": expire, 
        "type": "access",
        "aud": audience
    }
    import jwt
    return jwt.encode(to_encode, LIVE_JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

# --- API SCHEMAS ---
class TokenRequest(BaseModel):
    audience: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

v1_router = APIRouter(prefix="/api/v1")
secret_header = APIKeyHeader(name="X-Instance-Secret", auto_error=True)

@v1_router.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "OK", "database": "connected"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Status Error"
        )
        

@v1_router.post("/auth/token", response_model=TokenResponse)
def issue_tokens(
    payload: TokenRequest,
    secret: str = Depends(secret_header), 
    db: Session = Depends(get_db)
):
    if secret != settings.TOKEN_ISSUER_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token issuer secret"
        )

    access_token = create_access_token(audience=payload.audience)
    raw_refresh_token = generate_opaque_token()
    refresh_hash = hash_token(raw_refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db_session = AuthSession(
        token_hash=refresh_hash, 
        audience=payload.audience,
        expires_at=expires_at
    )
    db.add(db_session)
    db.commit()
    
    return {"access_token": access_token, "refresh_token": raw_refresh_token}


@v1_router.post("/auth/refresh", response_model=TokenResponse)
def refresh_access_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    incoming_hash = hash_token(payload.refresh_token)
    db_session = db.query(AuthSession).filter(AuthSession.token_hash == incoming_hash).first()
    if not db_session:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
        
    if db_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(db_session)
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")

    new_access_token = create_access_token(audience=db_session.audience)
    new_raw_refresh_token = generate_opaque_token()
    new_refresh_hash = hash_token(new_raw_refresh_token)

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

app.include_router(v1_router)

# --- AWS LAMBDA HANDLER ---
handler = Mangum(app)