import json
import re
import pytest
import logging
from email_verification import app, pending_verifications, generate_verification_code, send_verification_email

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO, format="%(message)s")

@pytest.fixture
def client():
    # Configure the Flask app for testing and create a test client.
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Clear pending_verifications before each test
        pending_verifications.clear()
        yield client

def test_generate_verification_code_length():
    code = generate_verification_code()
    assert isinstance(code, str)
    assert len(code) == 6
    print("test_generate_verification_code_length passed")

def test_generate_verification_code_alphanumeric():
    code = generate_verification_code()
    pattern = re.compile("^[A-Z0-9]{6}$")
    assert pattern.match(code)
    print("test_generate_verification_code_alphanumeric passed")

def test_send_verification_email_success(monkeypatch):
    # Create a dummy SMTP class to avoid real network calls.
    class DummySMTP:
        def __init__(self, server, port):
            pass
        def starttls(self):
            pass
        def login(self, sender, password):
            pass
        def sendmail(self, sender, receiver, message):
            # Check that sender and receiver are provided.
            assert sender is not None
            assert receiver is not None
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr("smtplib.SMTP", DummySMTP)
    test_email = "dummy@example.com"
    code = generate_verification_code()
    send_verification_email(test_email, code)
    print("test_send_verification_email_success passed")

def test_send_verification_endpoint_success(client):
    response = client.post("/send-verification", json={"email": "test@example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data.get("message") == "Verification email sent"
    token = data.get("token")
    assert token is not None and len(token) == 6
    assert token in pending_verifications
    print("test_send_verification_endpoint_success passed")

def test_send_verification_endpoint_missing_email(client):
    response = client.post("/send-verification", json={})
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    print("test_send_verification_endpoint_missing_email passed")

def test_verify_endpoint_success(client):
    # First, trigger a verification request to get a valid token.
    post_response = client.post("/send-verification", json={"email": "test@example.com"})
    post_data = post_response.get_json()
    token = post_data.get("token")
    # Now, verify the token using GET /verify.
    get_response = client.get(f"/verify?token={token}")
    assert get_response.status_code == 200
    assert b"successfully verified" in get_response.data
    assert token not in pending_verifications
    print("test_verify_endpoint_success passed")

def test_verify_endpoint_invalid_token(client):
    response = client.get("/verify?token=INVALID")
    assert response.status_code == 400
    assert b"Invalid or expired token." in response.data
    print("test_verify_endpoint_invalid_token passed")
