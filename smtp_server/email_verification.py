import os
import smtplib
import random
import string
from flask import Flask, request, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Read configuration values from environment variables
SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")  # Only needed if authentication is required
FLASK_HOST = os.getenv("FLASK_HOST", "localhost")
FLASK_PORT = os.getenv("FLASK_PORT", "5000")

app = Flask(__name__)

# In-memory store for verification codes (for demo only)
pending_verifications = {}

def generate_verification_code(length=6):
    """Generates a random alphanumeric verification code."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def send_verification_email(receiver_email, verification_code):
    """Sends an email with a verification code and link to the specified receiver."""
    verification_link = f"http://{FLASK_HOST}:{FLASK_PORT}/verify?token={verification_code}"
    
    subject = "Your Verification Code"
    body = (
        f"Hello,\n\n"
        f"Your verification code is: {verification_code}\n"
        f"Or click this link to verify: {verification_link}\n\n"
        "If you did not initiate this request, please secure your account immediately."
    )
    
    # Compose the email
    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # Start TLS if using a port that requires it (like 587)
            if SMTP_PORT in [587, 465]:
                server.starttls()
            if SENDER_PASSWORD:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, receiver_email, message.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")

@app.route("/send-verification", methods=["POST"])
def send_verification():
    """Endpoint to receive an email address and send a verification email."""
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Email is required"}), 400
    
    receiver_email = data["email"]
    verification_code = generate_verification_code()
    # Store the token with associated email (in production, use a persistent store with expiration)
    pending_verifications[verification_code] = receiver_email
    
    send_verification_email(receiver_email, verification_code)
    return jsonify({"message": "Verification email sent", "token": verification_code}), 200

@app.route("/verify", methods=["GET"])
def verify():
    """Endpoint that processes the verification link clicked by the user."""
    token = request.args.get("token")
    if token in pending_verifications:
        # Verification successful; remove token from store
        verified_email = pending_verifications.pop(token)
        return f"Email {verified_email} has been successfully verified!", 200
    else:
        return "Invalid or expired token.", 400

if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=int(FLASK_PORT), debug=True)
