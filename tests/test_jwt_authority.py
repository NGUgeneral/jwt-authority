import pytest
import jwt
from datetime import datetime, timedelta, timezone
from main import settings, AuthSession, hash_token

HEADERS = {"X-Instance-Secret": "test_issuer_secret_key_123!"}

def test_issue_tokens_success(client, db_session):
    """Verify that valid payload and secret yields signed JWT access and opaque refresh tokens."""
    payload = {"audience": "headsntails-core"}
    response = client.post("/api/v1/auth/token", json=payload, headers=HEADERS)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

    # Verify the JWT claims match our configuration parameters
    decoded = jwt.decode(data["access_token"], settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM], audience="headsntails-core")
    assert decoded["type"] == "access"
    assert decoded["aud"] == "headsntails-core"

    # Verify database side-effects: row persisted correctly
    expected_hash = hash_token(data["refresh_token"])
    db_record = db_session.query(AuthSession).filter(AuthSession.token_hash == expected_hash).first()
    assert db_record is not None
    assert db_record.audience == "headsntails-core"


def test_issue_tokens_unauthorized(client):
    """Verify perimeter barrier blocks token generation if signature secrets do not align."""
    payload = {"audience": "headsntails-core"}
    
    # 1. Missing secret header
    response = client.post("/api/v1/auth/token", json=payload)
    assert response.status_code == 403

    # 2. Invalid secret header values
    bad_headers = {"X-Instance-Secret": "compromised_secret"}
    response = client.post("/api/v1/auth/token", json=payload, headers=bad_headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token issuer secret"


def test_refresh_token_rotation_success(client, db_session):
    """Verify active refresh token accurately updates schema and rotates execution criteria."""
    # Build an existing token state
    initial_hash = hash_token("old_opaque_token_string")
    expiry = datetime.now(timezone.utc) + timedelta(days=1)
    session_record = AuthSession(token_hash=initial_hash, audience="platform-client", expires_at=expiry)
    db_session.add(session_record)
    db_session.commit()

    payload = {"refresh_token": "old_opaque_token_string"}
    response = client.post("/api/v1/auth/refresh", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] is not None
    assert data["refresh_token"] != "old_opaque_token_string"

    # Ensure old hash is no longer present and new token is active
    new_hash = hash_token(data["refresh_token"])
    assert db_session.query(AuthSession).filter(AuthSession.token_hash == initial_hash).first() is None
    assert db_session.query(AuthSession).filter(AuthSession.token_hash == new_hash).first() is not None


def test_refresh_token_expired(client, db_session):
    """Verify expired refresh components purge themselves automatically and block rotation."""
    past_expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
    token_str = "expired_token_value"
    session_record = AuthSession(token_hash=hash_token(token_str), audience="platform-client", expires_at=past_expiry)
    db_session.add(session_record)
    db_session.commit()

    payload = {"refresh_token": token_str}
    response = client.post("/api/v1/auth/refresh", json=payload)
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token expired"
    
    # Check table structure to verify the cascade deleted the session object row
    assert db_session.query(AuthSession).filter(AuthSession.token_hash == hash_token(token_str)).first() is None


def test_revoke_token_explicit(client, db_session):
    """Verify explicit execution request purges registration keys gracefully."""
    token_str = "active_token_to_kill"
    session_record = AuthSession(
        token_hash=hash_token(token_str), 
        audience="platform-client", 
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    db_session.add(session_record)
    db_session.commit()

    payload = {"refresh_token": token_str}
    response = client.post("/api/v1/auth/revoke", json=payload)
    
    assert response.status_code == 204
    assert db_session.query(AuthSession).filter(AuthSession.token_hash == hash_token(token_str)).first() is None


def test_health_check_endpoint(client):
    """Verify system reporting returns standard confirmation mappings."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "OK", "database": "connected"}