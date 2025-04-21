
from fastapi import (
    FastAPI, Depends, HTTPException, Path, Query, Request, BackgroundTasks, Form
)
from fastapi.responses import HTMLResponse, RedirectResponse # Added HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates # Added Templating
# from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, EmailStr
import uvicorn
import os
import pandas as pd
# import datetime
# import random
# import string
# import httpx # Added for async requests

# --- Middleware for Sessions ---
# from starlette.middleware.sessions import SessionMiddleware # Added for session support

# --- Configuration (reading from environment variables) ---

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
TOKEN_EXPIRATION_MINUTES = int(os.getenv("TOKEN_EXPIRATION_MINUTES", "30"))
RFM_PATH = os.getenv("RFM_PATH", "./rfm_scores.csv")
# APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
# --- NEW Configuration for CAPTCHA and Sessions ---
RFM_COMPOSITE_THRESHOLD = float(os.getenv("RFM_COMPOSITE_THRESHOLD", "400.0")) # e.g., Trigger if score > 400

# --- Initialize FastAPI App ---
app = FastAPI(
    title="RFM verify",
    description="Provides RFM scores, email verification, and CAPTCHA protection.",
    version="1.2.0"
)

# --- Add Session Middleware ---
# Needs a secret key to sign cookies. KEEP THIS SECRET.
# app.add_middleware(SessionMiddleware, secret_key=APP_SECRET_KEY)


# == RFM Endpoint ==
# def RFMlookup(ip_address: str = Path(...), db: Session = Depends(get_db)): # ... (keep existing logic) ...
#     print(f"Received RFM lookup request for IP: {ip_address}")
#     # ... (query logic) ...
#     try:
#         score_data = db.query(RFMScore).filter(RFMScore.src_ip == ip_address).first()
#         if score_data: return RFMResponse.from_orm(score_data)
#         else: raise HTTPException(status_code=404, detail=f"RFM scores not found for IP: {ip_address}")
#     except Exception as e:
#         print(f"[ERROR] RFM DB query failed for IP {ip_address}: {e}")
#         raise HTTPException(status_code=503, detail="Could not query RFM database.")

class RFMlookup:
    def __init__(self, path = "./rfm_scores.csv"):
        self.table = pd.read_csv(path)
        self.table["frequency"] = self.table["frequency"].rank(method="average", pct=True) * 100

    def lookup(self, ip_address: str):
        data = self.table[self.table["client_ip"] == ip_address].values
        if len(data) == 1:
            first = data[0]
            r = first[1]
            f = first[2]
            m = first[3]
            return (r, f, m)
        else:
            return (-1,-1,-1)

class RFMResult(BaseModel):
    suspicious: bool

class RfmRequest(BaseModel):
    ip_address: str = Field(..., description="The client IP address to check", example="8.8.8.8")

rfm_fetecher = RFMlookup(RFM_PATH)
# --- DDoS/Suspicion Check Function ---
@app.post(
    "/rfm", # Changed path, no variable part
    tags=["RFM Lookup"],
    response_model=RFMResult # Use the response model
)
async def is_potential_ddos(request_data: RfmRequest):
    """
    Checks if the client IP is suspicious based on RFM score.
    Returns True if suspicious (requires CAPTCHA), False otherwise.
    """
    client_ip = request_data.ip_address

    if not client_ip:
        return False # Cannot check without IP

    print(f"Checking suspicion level for IP: {client_ip}")
    try:
        # Query the RFM score from the database
        r ,f ,m = rfm_fetecher.lookup(client_ip)

        # # Thresholds (adjustable based on system behavior)
        HIGH_FREQUENCY = 50        # packets per minute
        LOW_MONETARY = 100          # bytes
        HIGH_MONETARY = 1200        # bytes
        LOW_RECENCY = 1             # seconds (i.e., very recent)

        if r == -1:
            suspicious = True
        if r < LOW_RECENCY and f > HIGH_FREQUENCY:
            if m < LOW_MONETARY or m > HIGH_MONETARY:
                suspicious = True
            else: 
                suspicious = False
        elif f <= HIGH_FREQUENCY:
            suspicious = False
        else:
            suspicious = True
        return RFMResult(suspicious=suspicious)            

    except Exception as e:
        print(f"[ERROR] Database error checking RFM score for {client_ip}: {e}")
        # Fail safe: treat as not suspicious if DB query fails? Or block?
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while processing IP {client_ip}"
        ) # Defaulting to not suspicious on error

# --- Run Instructions ---
if __name__ == "__main__":
     print(f"Starting Uvicorn server on {API_HOST}:{API_PORT}...")
     print("Ensure DB, MailHog (if used), and other services are running.")
     print(f"Access API docs/app at http:#{API_HOST}:{API_PORT}/")
     uvicorn.run("rfm_api:app", host=API_HOST, port=API_PORT, reload=True) # Added reload for dev
