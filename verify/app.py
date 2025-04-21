from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import os
import time
from collections import defaultdict
import csv # <-- Import csv module
from datetime import datetime # <-- Import datetime for timestamp
import logging

app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.getenv("APP_SECRET_KEY", 'a-fallback-secret-key-for-dev') # Use env var or a default for dev

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
FASTAPI_BASE_URL = os.getenv("FASTAPI_BASE_URL")
TIME_WINDOW = 60
MAX_REQUESTS = 10 # Lowered for easier testing/simulation if needed
RFM_ENDPOINT      = "/rfm"                       # FastAPI route
TIMEOUT_SECONDS   = 1.5  

# --- Logging Configuration ---
LOG_DIR = 'network_logs' # Directory to store logs (relative to app.py)
LOG_FILE = os.path.join(LOG_DIR, f"requests.csv") # Daily log file  _{datetime.now().strftime('%Y%m%d')}
LOG_HEADER = LOG_HEADER = ['timestamp', 'client_ip', 'src_port', 'method', 'path', 'http_body_length', 'user_agent', 'referer']

# --- Global State (In-memory Rate Limiting) ---
ip_tracker = defaultdict(lambda: {'count': 0, 'window_start': 0})

# --- Helper Functions ---
def ensure_log_dir_exists():
    """Creates the log directory if it doesn't exist."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        print(f"Log directory '{LOG_DIR}' ensured.")
    except OSError as e:
        app.logger.error(f"Error creating log directory '{LOG_DIR}': {e}")
        # Depending on severity, you might want to exit or handle differently
        print(f"CRITICAL: Could not create log directory {LOG_DIR}. Logging disabled.")

def reset_tracker():
    """Clears the global ip_tracker."""
    global ip_tracker
    ip_tracker.clear()

# --- Request Logging ---
@app.before_request
def log_request_info():
    """
    Log application-level request info.
    NOTE: src_port is non-standard and may be missing/inaccurate.
    NOTE: http_body_length is Content-Length header, NOT packet size.
    """
    ensure_log_dir_exists()
    if request.path.startswith('/static'):
        return

    timestamp = datetime.now().isoformat()
    client_ip = request.remote_addr
    # --- Attempt to get source port (non-standard, use with caution) ---
    src_port = request.environ.get('REMOTE_PORT', 'N/A')
    # --------------------------------------------------------------------
    method = request.method
    path = request.path
    # --- Get HTTP Content-Length header (body size only) ---
    http_body_length = request.content_length if request.content_length is not None else 0
    # --------------------------------------------------------
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')

    log_entry = [
        timestamp,
        client_ip,
        src_port,
        method,
        path,
        http_body_length,
        user_agent,
        referer
    ]

    try:
        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists or os.path.getsize(LOG_FILE) == 0:
                writer.writerow(LOG_HEADER)
            writer.writerow(log_entry)
    except IOError as e:
        # Use Flask's logger for application errors
        app.logger.error(f"Error writing to request log file {LOG_FILE}: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error during request logging: {e}")

# --- DDoS Rate Limiting ---
def is_potential_ddos(client_ip, request_path):
    # (Your existing is_potential_ddos function - unchanged)
    # ... (Keep the function exactly as you had it) ...
    print(f"Checking request from {client_ip} to {request_path}")
    current_time = time.time()
    tracker = ip_tracker[client_ip]
    count = tracker['count']
    window_start = tracker['window_start']
    if current_time - window_start > TIME_WINDOW:
        print(f"Resetting window for IP: {client_ip}")
        ip_tracker[client_ip]['count'] = 1
        ip_tracker[client_ip]['window_start'] = current_time
        print("Request deemed not suspicious (new window).")
        return False
    else:
        ip_tracker[client_ip]['count'] += 1
        count = ip_tracker[client_ip]['count']
        if count > MAX_REQUESTS:
            print(f"!!! Potential DDoS detected !!! IP: {client_ip} exceeded {MAX_REQUESTS} requests in {TIME_WINDOW}s (Count: {count})")
            if is_ddos_lookup_RFM(client_ip):
                print(f"from RFM look up {client_ip} seem to be new user with high fequency/capacity mark as supecious and begin rate limit")
                return True
            else:
                print(f"from RFM look up this seem to be large just subnet continue allow IP: {client_ip}")
                return False
        else:
            print("Request deemed not suspicious.")
            return False

# --- Placeholder for RFM/Other Logic (Keep as is) ---
def is_ddos_lookup_RFM(client_ip):
    # (Your existing placeholder function - unchanged)
    # ... (Keep the function exactly as you had it) ...
    print(f"Checking request from {client_ip}")
    if client_ip == '127.0.0.1':
         print("IP matches example condition, flagging as potential DDoS.")
         return True
    try:
        url      = f"{FASTAPI_BASE_URL}{RFM_ENDPOINT}"
        # FastAPI returns plain text ("true"/"false"/"notfound") or JSON
        payload = {
            "ip_address": client_ip
        }
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json' # Indicate we prefer JSON response
        }

        try:
            response = requests.post(
                url,
                json=payload,       # requests handles json serialization and Content-Type
                headers=headers,    # Still good to include Accept header
                timeout=TIMEOUT_SECONDS
            )

            # Raise an exception for bad status codes (4xx or 5xx)
            response.raise_for_status()

            # If successful (2xx status code), parse the JSON response
            result_data = response.json()
            app.logger.debug(f"[RFM-lookup] Received JSON response: {result_data}")

            # Extract the 'suspicious' field safely using .get()
            suspicious = bool(result_data.get("suspicious", False)) # Default to False if key missing

            app.logger.info(f"[RFM-lookup] RFM service indicated suspicious={suspicious} for IP {client_ip}")
            return suspicious
        except:
            print("error rfm look up")
            return False 

    except requests.exceptions.HTTPError as http_err:

        # Accept either format
        if isinstance(payload, dict):
            suspicious = bool(payload.get("suspicious"))
        else:
            suspicious = (payload == "true")

        print(f"[RFM‑lookup] FastAPI said suspicious={suspicious}")
        return suspicious

    except requests.RequestException as exc:
        # Network / FastAPI error – log and allow traffic by default
        print(f"[RFM‑lookup] ERROR contacting RFM service: {exc}")
        return False
    print("Request deemed not suspicious.")
    return False

# --- Routes (Keep your existing routes) ---
@app.route('/')
def index():
    # ... (your existing index route) ...
    return render_template('index.html') # Assuming you have index.html

@app.route('/sensitive-data', strict_slashes=False)
def sensitive_data():
    # ... (your existing sensitive_data route using is_potential_ddos) ...
    client_ip = request.remote_addr
    if session.get('is_human_verified'):
        print("User already verified in this session.")
        return render_template('sensitive_page.html', message="Access granted (already verified).") # Assuming sensitive_page.html
    if is_potential_ddos(client_ip, request.path):

        print("Potential DDoS detected. Redirecting to CAPTCHA.")
        session['intended_url'] = request.url
        return redirect(url_for('verify_captcha_page'))
    else:
        print("Not suspicious, granting access for this request.")
        return render_template('sensitive_page.html', message="Access granted (not flagged as suspicious).")

@app.route('/verify', methods=['GET', 'POST'])
def verify_captcha_page():
    # ... (your existing verify_captcha_page route) ...
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        remote_ip = request.remote_addr
        if not token:
            flash("CAPTCHA verification is required.", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY) # Assuming verify_captcha.html
        payload = {'secret': RECAPTCHA_SECRET_KEY, 'response': token, 'remoteip': remote_ip}
        try:
            response = requests.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=5)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
             flash(f"Error verifying CAPTCHA: {e}", "error")
             return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)
        print(f"Google verification result: {result}")
        if result.get("success"):
            flash("Verification successful!", "success")
            session['is_human_verified'] = True
            intended_url = session.pop('intended_url', url_for('index'))
            return render_template('verified_ok.html', intended_url=intended_url) # Assuming verified_ok.html
        else:
            error_codes = result.get("error-codes", [])
            flash(f"CAPTCHA verification failed. Please try again. Errors: {error_codes}", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)
    # GET Request
    if not RECAPTCHA_SITE_KEY or "YOUR_RECAPTCHA" in RECAPTCHA_SITE_KEY:
         flash("FATAL ERROR: reCAPTCHA Site Key is not configured!", "error")
         return "Server configuration error: reCAPTCHA Site Key missing.", 500
    return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)


# --- Main Execution ---
if __name__ == '__main__':
    # Ensure log dir exists on startup as well
    ensure_log_dir_exists()
    # Set debug=False for production!
    app.run(debug=True, host='0.0.0.0', port=5000)
