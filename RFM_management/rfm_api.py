
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
import random
import string
import httpx # Added for async requests

# --- Middleware for Sessions ---
from starlette.middleware.sessions import SessionMiddleware # Added for session support

# Import necessary components from database_utils
from database_utils import (
    RFMScore, get_db, create_db_and_tables, engine
)

# --- Configuration (reading from environment variables) ---
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
TOKEN_EXPIRATION_MINUTES = int(os.getenv("TOKEN_EXPIRATION_MINUTES", "30"))

# --- NEW Configuration for CAPTCHA and Sessions ---
# IMPORTANT: Generate a strong, unique secret key for production!
# Use: python -c 'import os; print(os.urandom(24))'
APP_SECRET_KEY = os.getenv("c3eea4e72ec11981e2c48798c13f634679b7c955433ae647", "default_insecure_secret_key_replace_me")
RECAPTCHA_SITE_KEY = os.getenv("6LcvnhorAAAAACkm2jzB1gGUvDkHgFGrHbRDi5R6", "YOUR_RECAPTCHA_V2_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("6LcvnhorAAAAAN8BYM_6Bklvojrtrm9eOxhcHV2b", "YOUR_RECAPTCHA_V2_SECRET_KEY")
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

# # --- Database Initialization ---
# if engine:
#     create_db_and_tables() # Creates rfm_scores and verification_tokens tables
# else:
#     print("[ERROR] API cannot start: Database engine not initialized.")

# --- Pydantic Models (Keep existing) ---
class RFMResponse(BaseModel): # ... (keep definition) ...
    R: float = Field(...)
    F: float = Field(...)
    M: float = Field(...)
    composite_score: float | None = Field(None)
    last_updated: str | None = Field(None)
    class Config: orm_mode = True

# == RFM Endpoint ==
def RFMlookup(ip_address: str = Path(...), db: Session = Depends(get_db)): # ... (keep existing logic) ...
    print(f"Received RFM lookup request for IP: {ip_address}")
    # ... (query logic) ...
    try:
        score_data = db.query(RFMScore).filter(RFMScore.src_ip == ip_address).first()
        if score_data: return RFMResponse.from_orm(score_data)
        else: raise HTTPException(status_code=404, detail=f"RFM scores not found for IP: {ip_address}")
    except Exception as e:
        print(f"[ERROR] RFM DB query failed for IP {ip_address}: {e}")
        raise HTTPException(status_code=503, detail="Could not query RFM database.")

# --- DDoS/Suspicion Check Function ---
@app.get( # ... (keep existing decorator and signature) ...
    "/rfm/{ip_address}", response_model=RFMResponse, tags=["RFM Lookup"], #...
)
async def is_potential_ddos(db: Session, client_ip: str) -> str:
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
            print(f"No RFM score found for {client_ip}.checking if he is human.")
            return "need captcha"

    except Exception as e:
        print(f"[ERROR] Database error checking RFM score for {client_ip}: {e}")
        # Fail safe: treat as not suspicious if DB query fails? Or block?
        return False # Defaulting to not suspicious on error

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
