import pytest
import os

# 1. Force override environment variables before any imports
# Using a shared memory cache string ensures all engine instances hit the exact same database space!
SHARED_TEST_DB = "sqlite:///:memory:?cache=shared"
os.environ["DATABASE_URL"] = SHARED_TEST_DB
os.environ["TOKEN_ISSUER_SECRET"] = "test_issuer_secret_key_123!"
os.environ["JWT_SECRET_KEY"] = "test_jwt_signing_secret_key_456!"
os.environ["APP_ENV"] = "local"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import main

# 2. Setup the engine using the exact same shared memory connection string
test_engine = create_engine(
    SHARED_TEST_DB, 
    connect_args={"check_same_thread": False}
)

# 3. Explicitly overwrite main's globals to align the contexts perfectly
main.engine = test_engine
main.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="function")
def db_session():
    """Fresh database schema and transaction session per test function."""
    # We must explicitly keep a persistent connection open to the shared cache,
    # otherwise SQLite will wipe the entire DB from memory when the session closes.
    connection = test_engine.connect()
    main.Base.metadata.create_all(bind=connection)
    
    session = main.SessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        main.Base.metadata.drop_all(bind=connection)
        connection.close()

@pytest.fixture(scope="function")
def client(db_session):
    """Test client with overridden dependency injection container hooks."""
    def _get_test_db():
        try:
            yield db_session
        finally:
            pass

    main.app.dependency_overrides[main.get_db] = _get_test_db
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.clear()