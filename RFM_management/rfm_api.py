
from fastapi import (
    FastAPI, Depends, HTTPException, Path, Query, Request, BackgroundTasks, Form
)
from fastapi.responses import HTMLResponse, RedirectResponse # Added HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates # Added Templating
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, EmailStr
import uvicorn
import os
import datetime
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import httpx # Added for async requests

# --- Middleware for Sessions ---
from starlette.middleware.sessions import SessionMiddleware # Added for session support

# Import necessary components from database_utils
from database_utils import (
    RFMScore, VerificationToken, get_db, create_db_and_tables, engine
)

# --- Configuration (reading from environment variables) ---
# (Keep existing DB, SMTP, API Host/Port, Token Expiry config)
SMTP_SERVER = os.getenv("SMTP_SERVER", "mailhog")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@example.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
TOKEN_EXPIRATION_MINUTES = int(os.getenv("TOKEN_EXPIRATION_MINUTES", "30"))

# --- NEW Configuration for CAPTCHA and Sessions ---
# IMPORTANT: Generate a strong, unique secret key for production!
# Use: python -c 'import os; print(os.urandom(24))'
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "default_insecure_secret_key_replace_me") # CHANGE THIS!
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "YOUR_RECAPTCHA_V2_SITE_KEY") # From Google Admin
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "YOUR_RECAPTCHA_V2_SECRET_KEY") # From Google Admin
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
# Define RFM Score Threshold for triggering CAPTCHA (Example)
RFM_COMPOSITE_THRESHOLD = float(os.getenv("RFM_COMPOSITE_THRESHOLD", "400.0")) # e.g., Trigger if score > 400

# --- Initialize FastAPI App ---
app = FastAPI(
    title="RFM, Verification & CAPTCHA API",
    description="Provides RFM scores, email verification, and CAPTCHA protection.",
    version="1.2.0"
)

# --- Add Session Middleware ---
# Needs a secret key to sign cookies. KEEP THIS SECRET.
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET_KEY)

# --- Configure Templating ---
templates = Jinja2Templates(directory="templates")

# --- Database Initialization ---
if engine:
    create_db_and_tables() # Creates rfm_scores and verification_tokens tables
else:
    print("[ERROR] API cannot start: Database engine not initialized.")

# --- Pydantic Models (Keep existing) ---
class RFMResponse(BaseModel): # ... (keep definition) ...
    R: float = Field(...)
    F: float = Field(...)
    M: float = Field(...)
    composite_score: float | None = Field(None)
    last_updated: str | None = Field(None)
    class Config: orm_mode = True

class SendVerificationRequest(BaseModel): # ... (keep definition) ...
      email: EmailStr

class VerificationResponse(BaseModel): # ... (keep definition) ...
      message: str

class ErrorResponse(BaseModel): # ... (keep definition) ...
      detail: str

# --- Helper Functions ---
# (Keep existing generate_verification_token, send_verification_email)
def generate_verification_token(length=32): # ... (keep definition) ...
      characters = string.ascii_letters + string.digits
      return ''.join(random.choice(characters) for _ in range(length))

def send_verification_email(receiver_email: str, verification_token: str, request: Request): # ... (keep definition) ...
    base_url = str(request.base_url).rstrip('/')
    verification_link = f"{base_url}/verify-email?token={verification_token}" # Changed path slightly for clarity
    # ... rest of email sending logic ...
    subject = "Verify Your Email Address"
    body = f"Hello,\n\nPlease click the link below...\n{verification_link}\n..."
    message = MIMEMultipart()
    # ... (set headers, attach body) ...
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # ... (TLS/login logic) ...
             if SMTP_PORT == 587: server.starttls()
             if SENDER_PASSWORD: server.login(SENDER_EMAIL, SENDER_PASSWORD)
             server.sendmail(SENDER_EMAIL, receiver_email, message.as_string())
        print(f"Verification email successfully sent to {receiver_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email via {SMTP_SERVER}:{SMTP_PORT}: {e}")
        # Don't raise HTTPException here as it's a background task

# --- DDoS/Suspicion Check Function ---
def is_potential_ddos(db: Session, client_ip: str) -> bool:
    """
    Checks if the client IP is suspicious based on RFM score.
    Returns True if suspicious (requires CAPTCHA), False otherwise.
    """
    if not client_ip:
        return False # Cannot check without IP

    print(f"Checking suspicion level for IP: {client_ip}")
    try:
        # Query the RFM score from the database
        score_data = db.query(RFMScore).filter(RFMScore.src_ip == client_ip).first()

        if score_data and score_data.composite_score is not None:
            print(f"Found RFM score for {client_ip}: {score_data.composite_score}")
            # --- !!! Your Logic Here !!! ---
            # Example: Trigger CAPTCHA if composite score exceeds a threshold
            if score_data.composite_score >= RFM_COMPOSITE_THRESHOLD:
                print(f"Score {score_data.composite_score} >= threshold {RFM_COMPOSITE_THRESHOLD}. Flagging as suspicious.")
                return True
            else:
                 print(f"Score {score_data.composite_score} < threshold {RFM_COMPOSITE_THRESHOLD}. Not suspicious.")
                 return False
        else:
            # No score found - decide how to handle this.
            # Options: Treat as not suspicious, treat as suspicious, use default score?
            print(f"No RFM score found for {client_ip}. Treating as not suspicious.")
            return False

    except Exception as e:
        print(f"[ERROR] Database error checking RFM score for {client_ip}: {e}")
        # Fail safe: treat as not suspicious if DB query fails? Or block?
        return False # Defaulting to not suspicious on error

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse, tags=["General"])
async def read_index(request: Request):
    """Serves the home page."""
    return templates.TemplateResponse("index.html", {"request": request})

# == RFM Endpoint ==
@app.get( # ... (keep existing decorator and signature) ...
    "/rfm/{ip_address}", response_model=RFMResponse, tags=["RFM Lookup"], #...
)
async def RFMlookup(ip_address: str = Path(...), db: Session = Depends(get_db)): # ... (keep existing logic) ...
    print(f"Received RFM lookup request for IP: {ip_address}")
    # ... (query logic) ...
    try:
        score_data = db.query(RFMScore).filter(RFMScore.src_ip == ip_address).first()
        if score_data: return RFMResponse.from_orm(score_data)
        else: raise HTTPException(status_code=404, detail=f"RFM scores not found for IP: {ip_address}")
    except Exception as e:
        print(f"[ERROR] RFM DB query failed for IP {ip_address}: {e}")
        raise HTTPException(status_code=503, detail="Could not query RFM database.")


# == Email Verification Endpoints ==
@app.post( # ... (keep existing decorator and signature) ...
    "/send-verification", response_model=VerificationResponse, status_code=202, tags=["Email Verification"], #...
)
async def request_verification(payload: SendVerificationRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)): # ... (keep existing logic) ...
    receiver_email = payload.email
    # ... (generate token, store in DB) ...
    token = generate_verification_token()
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    db_token = VerificationToken(email=receiver_email, token=token, expires_at=expires, is_used=False)
    try:
        db.add(db_token)
        db.commit()
    except Exception as e:
        db.rollback(); raise HTTPException(status_code=503, detail="DB error")
    background_tasks.add_task(send_verification_email, receiver_email, token, request)
    return VerificationResponse(message=f"Verification email initiated for {receiver_email}.")

# Renamed path slightly to avoid conflict with CAPTCHA verify
@app.get( # ... (keep existing decorator and signature, but change path) ...
    "/verify-email", response_model=VerificationResponse, tags=["Email Verification"], #...
)
async def verify_email(token: str = Query(...), db: Session = Depends(get_db)): # ... (keep existing logic) ...
    # ... (find token, check expiry/used, mark as used) ...
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        db_token = db.query(VerificationToken).filter(VerificationToken.token == token, VerificationToken.is_used == False, VerificationToken.expires_at > now).first()
        if not db_token: raise HTTPException(status_code=400, detail="Invalid/Expired/Used token.")
        verified_email = db_token.email
        db_token.is_used = True
        db.commit()
        return VerificationResponse(message=f"Email {verified_email} has been successfully verified.")
    except HTTPException as e: raise e
    except Exception as e: db.rollback(); raise HTTPException(status_code=503, detail="DB error")


# == CAPTCHA Protected Route ==
@app.get("/sensitive-data", response_class=HTMLResponse, tags=["Protected Content"])
async def sensitive_data(request: Request, db: Session = Depends(get_db)):
    """
    Example route protected by DDoS check + CAPTCHA.
    """
    client_ip = request.client.host if request.client else None

    # 1. Check if user is already CAPTCHA verified in this session
    if request.session.get('is_human_verified'):
        print(f"IP {client_ip}: Access granted (session verified).")
        return templates.TemplateResponse("sensitive_page.html", {
            "request": request,
            "message": "Access granted (already verified in this session)."
        })

    # 2. Perform DDoS/suspicion check using RFM score
    if is_potential_ddos(db, client_ip):
        print(f"IP {client_ip}: Potential DDoS detected. Redirecting to CAPTCHA.")
        # Store the URL they were trying to access
        request.session['intended_url'] = str(request.url)
        # Redirect to the CAPTCHA verification page
        captcha_url = request.url_for('verify_captcha_page')
        return RedirectResponse(url=captcha_url, status_code=307) # Use 307 to preserve method if needed
    else:
        # Not suspicious, grant access (or force CAPTCHA always if desired)
        print(f"IP {client_ip}: Not suspicious. Access granted for this request.")
        # Optional: You could still force CAPTCHA here by removing this else
        # and always redirecting if not session.get('is_human_verified')
        return templates.TemplateResponse("sensitive_page.html", {
            "request": request,
            "message": "Access granted (not flagged as suspicious)."
        })


# == CAPTCHA Verification Page ==
@app.get("/verify-captcha", response_class=HTMLResponse, tags=["CAPTCHA"])
async def verify_captcha_page(request: Request):
    """Displays the CAPTCHA form."""
    # Retrieve flashed messages if any (passed via session in POST handler)
    messages = request.session.pop('flash_messages', []) # Get and clear messages
    print(f"Displaying CAPTCHA page. Messages: {messages}")
    return templates.TemplateResponse("verify_captcha.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "messages": messages # Pass messages to template
    })

@app.post("/verify-captcha", response_class=HTMLResponse, tags=["CAPTCHA"])
async def handle_captcha_verification(
    request: Request,
    g_recaptcha_response: str = Form(...) # Get token from form data
):
    """Handles the submission from the CAPTCHA form."""
    token = g_recaptcha_response
    remote_ip = request.client.host if request.client else None
    messages = [] # Store messages for re-rendering form if needed

    if not token:
        messages.append(("error", "CAPTCHA verification is required."))
        request.session['flash_messages'] = messages # Store message for GET redirect
        return RedirectResponse(url=request.url_for('verify_captcha_page'), status_code=303) # PRG pattern

    # Server-side verification with Google
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': token,
    }
    if remote_ip:
        payload['remoteip'] = remote_ip

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=10)
            response.raise_for_status() # Raise exception for bad status codes
            result = response.json()
            print(f"Google verification result for IP {remote_ip}: {result}")
        except httpx.RequestError as e:
             print(f"[ERROR] httpx request to Google failed: {e}")
             messages.append(("error", f"Error communicating with verification server: {e}"))
             request.session['flash_messages'] = messages
             return RedirectResponse(url=request.url_for('verify_captcha_page'), status_code=303)
        except Exception as e: # Catch other potential errors like JSON decoding
             print(f"[ERROR] Unexpected error during CAPTCHA verification: {e}")
             messages.append(("error", "An unexpected error occurred during verification."))
             request.session['flash_messages'] = messages
             return RedirectResponse(url=request.url_for('verify_captcha_page'), status_code=303)

    if result.get("success"):
         # --- Verification Successful ---
        print(f"IP {remote_ip}: CAPTCHA verification successful.")
        request.session['is_human_verified'] = True # Mark session as verified

        # Redirect to the originally intended URL, or fallback to index
        intended_url = request.session.pop('intended_url', request.url_for('read_index'))
        print(f"Redirecting verified user to: {intended_url}")
        # Option 1: Redirect directly
        # return RedirectResponse(url=intended_url, status_code=303)
        # Option 2: Show a success page first
        return templates.TemplateResponse("verified_ok.html", {
            "request": request,
            "intended_url": intended_url
        })
    else:
        # --- Verification Failed ---
        error_codes = result.get("error-codes", [])
        print(f"IP {remote_ip}: CAPTCHA verification failed. Errors: {error_codes}")
        messages.append(("error", f"CAPTCHA verification failed. Please try again. Errors: {error_codes}"))
        request.session['flash_messages'] = messages
        return RedirectResponse(url=request.url_for('verify_captcha_page'), status_code=303)


# --- Run Instructions ---
if __name__ == "__main__":
     # Check essential config
     if "YOUR_RECAPTCHA" in RECAPTCHA_SITE_KEY or "YOUR_RECAPTCHA" in RECAPTCHA_SECRET_KEY:
         print("\n" + "*"*60)
         print("FATAL ERROR: reCAPTCHA keys are not configured in environment variables.")
         print("Please set RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY.")
         print("*"*60 + "\n")
     if "default_insecure" in APP_SECRET_KEY:
          print("\n" + "*"*60)
          print("WARNING: Using default insecure APP_SECRET_KEY. Please set a strong secret.")
          print("Generate one using: python -c 'import os; print(os.urandom(24))'")
          print("*"*60 + "\n")

     print(f"Starting Uvicorn server on {API_HOST}:{API_PORT}...")
     print("Ensure DB, MailHog (if used), and other services are running.")
     print(f"Access API docs/app at http://{API_HOST}:{API_PORT}/")
     uvicorn.run("rfm_api:app", host=API_HOST, port=API_PORT, reload=True) # Added reload for dev
