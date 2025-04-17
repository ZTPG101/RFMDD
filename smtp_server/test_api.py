
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock
import datetime

# Import your FastAPI app and database models/dependencies
# Adjust the import path if your structure is different
from rfm_api import app, get_db, RFMScore, VerificationToken
from database_utils import Base # Import Base for creating tables in test DB

# --- Test Database Setup ---
# Use an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} # Needed for SQLite
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables in the test database before tests run
Base.metadata.create_all(bind=engine)

# --- Fixture to Override DB Dependency ---
@pytest.fixture(scope="function") # Use function scope to reset DB for each test
def db_session():
    """Yields a clean database session for each test."""
    Base.metadata.drop_all(bind=engine) # Drop existing tables
    Base.metadata.create_all(bind=engine) # Recreate tables
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Fixture for Test Client ---
@pytest.fixture(scope="function")
def client(db_session):
    """Provides a TestClient with overridden DB dependency."""
    # Override the get_db dependency to use the test database
    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close() # Ensure session is closed

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    # Clean up dependency override after tests
    app.dependency_overrides = {}


# --- Test Helper Function ---
def add_rfm_record(db_session, ip, r, f, m, comp, updated):
    """Adds a sample RFM record to the test database."""
    record = RFMScore(src_ip=ip, r_score=r, f_score=f, m_score=m, composite_score=comp, last_updated=updated)
    db_session.add(record)
    db_session.commit()
    return record

# --- RFM Endpoint Tests ---

def test_rfm_lookup_success(client, db_session):
    # Arrange: Add data to test DB
    ip = "192.168.1.1"
    add_rfm_record(db_session, ip, 5.0, 4.0, 3.0, 543.0, datetime.datetime.now().isoformat())

    # Act
    response = client.get(f"/rfm/{ip}")

    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["R"] == 5.0
    assert data["F"] == 4.0
    assert data["M"] == 3.0
    assert data["composite_score"] == 543.0

def test_rfm_lookup_not_found(client):
    # Act
    response = client.get("/rfm/1.2.3.4") # IP not in DB

    # Assert
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

# --- Email Verification Endpoint Tests ---

@patch("rfm_api.send_verification_email") # Mock the actual email sending function
def test_send_verification_success(mock_send_email, client, db_session):
    # Arrange
    test_email = "test@example.com"

    # Act
    response = client.post("/send-verification", json={"email": test_email})

    # Assert
    assert response.status_code == 202 # Accepted
    assert "Verification email initiated" in response.json()["message"]

    # Check if token was stored in the DB
    token_record = db_session.query(VerificationToken).filter(VerificationToken.email == test_email).first()
    assert token_record is not None
    assert token_record.token is not None
    assert not token_record.is_used

    # Check if background task was called (basic check)
    mock_send_email.assert_called_once()
    call_args = mock_send_email.call_args[0] # Get positional arguments
    assert call_args[0] == test_email # receiver_email
    assert call_args[1] == token_record.token # verification_token
    # assert isinstance(call_args[2], Request) # Check if request object was passed

def test_send_verification_invalid_email(client):
    # Act
    response = client.post("/send-verification", json={"email": "not-an-email"})

    # Assert
    assert response.status_code == 422 # Unprocessable Entity (Pydantic validation)

@patch("rfm_api.send_verification_email") # Mock email sending
def test_verify_email_success(mock_send_email, client, db_session):
    # Arrange: First send a verification request to get a token in the DB
    test_email = "verify@example.com"
    client.post("/send-verification", json={"email": test_email})
    token_record = db_session.query(VerificationToken).filter(VerificationToken.email == test_email).first()
    valid_token = token_record.token

    # Act: Verify the token
    response = client.get(f"/verify?token={valid_token}")

    # Assert
    assert response.status_code == 200
    assert f"Email {test_email} has been successfully verified" in response.json()["message"]

    # Check if token is marked as used
    db_session.refresh(token_record) # Refresh object state from DB
    assert token_record.is_used is True

def test_verify_email_invalid_token(client):
    # Act
    response = client.get("/verify?token=INVALIDTOKEN")

    # Assert
    assert response.status_code == 400
    assert "Invalid, expired, or already used token" in response.json()["detail"]

@patch("rfm_api.send_verification_email")
def test_verify_email_expired_token(mock_send_email, client, db_session):
    # Arrange: Add an expired token manually
    test_email = "expired@example.com"
    token = "EXPIREDTOKEN123"
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_time = now - datetime.timedelta(minutes=60) # Expired 60 mins ago
    db_token = VerificationToken(
        email=test_email, token=token, created_at=expired_time, expires_at=expired_time, is_used=False
    )
    db_session.add(db_token)
    db_session.commit()

    # Act
    response = client.get(f"/verify?token={token}")

    # Assert
    assert response.status_code == 400
    assert "Invalid, expired, or already used token" in response.json()["detail"]


@patch("rfm_api.send_verification_email")
def test_verify_email_used_token(mock_send_email, client, db_session):
    # Arrange: Add a token and mark it as used
    test_email = "used@example.com"
    client.post("/send-verification", json={"email": test_email})
    token_record = db_session.query(VerificationToken).filter(VerificationToken.email == test_email).first()
    valid_token = token_record.token
    token_record.is_used = True # Mark as used
    db_session.commit()

    # Act
    response = client.get(f"/verify?token={valid_token}")

    # Assert
    assert response.status_code == 400
    assert "Invalid, expired, or already used token" in response.json()["detail"]


# --- Mocking smtplib (Example if needed for deeper testing) ---
@patch('smtplib.SMTP') # Patch the SMTP class
def test_send_email_function_logic(mock_smtp_class):
    # Arrange
    mock_server = MagicMock() # Mock the SMTP server instance
    mock_smtp_class.return_value.__enter__.return_value = mock_server # Mock the context manager

    receiver = "recipient@example.com"
    token = "DUMMYTOKEN"
    # Create a dummy request object (might need more attributes depending on usage)
    class DummyRequest:
        base_url = "http://testserver/"
    dummy_request = DummyRequest()

    # Act
    from rfm_api import send_verification_email # Import locally to use patch
    send_verification_email(receiver, token, dummy_request)

    # Assert
    mock_smtp_class.assert_called_with(os.getenv("SMTP_SERVER", "mailhog"), int(os.getenv("SMTP_PORT", "1025"))) # Check connection args
    mock_server.sendmail.assert_called_once() # Check if sendmail was called
    args, kwargs = mock_server.sendmail.call_args
    assert args[0] == os.getenv("SENDER_EMAIL", "noreply@example.com") # From
    assert args[1] == receiver # To
    assert f"token={token}" in args[2] # Check if token is in the message body
