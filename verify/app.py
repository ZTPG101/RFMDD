from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, make_response
import requests
import os
import time
from collections import defaultdict
import csv
from datetime import datetime, timedelta # Import timedelta
import logging

app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.getenv("APP_SECRET_KEY", 'a-fallback-secret-key-for-dev')

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

# Rate Limiting & Blocking Configuration
TIME_WINDOW = 60  # Seconds for rate limit window
MAX_REQUESTS = 10 # Lowered for easier testing
BLOCK_DURATION = 60 # Seconds to block the IP after exceeding the limit

# --- Logging Configuration ---
LOG_DIR = 'network_logs'
LOG_FILE = os.path.join(LOG_DIR, f"requests_{datetime.now().strftime('%Y%m%d')}.csv")
LOG_HEADER = ['timestamp', 'client_ip', 'src_port', 'method', 'path', 'http_body_length', 'user_agent', 'referer', 'status_code', 'blocked'] # Added status_code and blocked

# --- Global State (In-memory Rate Limiting & Blocking) ---
# Structure: ip -> {'count': int, 'window_start': float, 'blocked_until': float}
# blocked_until: Timestamp (time.time()) when the block expires. 0 or past time means not blocked.
ip_tracker = defaultdict(lambda: {'count': 0, 'window_start': 0, 'blocked_until': 0})

# --- Helper Functions ---
def ensure_log_dir_exists():
    """Creates the log directory if it doesn't exist."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        # print(f"Log directory '{LOG_DIR}' ensured.") # Less verbose
    except OSError as e:
        app.logger.error(f"Error creating log directory '{LOG_DIR}': {e}")
        print(f"CRITICAL: Could not create log directory {LOG_DIR}. Logging disabled.")

def reset_tracker():
    """Clears the global ip_tracker."""
    global ip_tracker
    ip_tracker.clear()
    print("IP tracker cleared.")

# --- Request Processing Hooks ---

@app.before_request
def rate_limit_and_log():
    """
    Checks rate limits, blocks if necessary, and logs request info.
    This runs BEFORE route handlers.
    """
    # 1. Skip static files for rate limiting and detailed logging
    if request.path.startswith('/static'):
        return None # Allow request to proceed

    client_ip = request.remote_addr
    current_time = time.time()
    tracker = ip_tracker[client_ip]

    # --- Check if currently blocked ---
    if tracker['blocked_until'] > current_time:
        app.logger.warning(f"Blocked IP {client_ip} attempted access to {request.path}. Block expires at {datetime.fromtimestamp(tracker['blocked_until']).isoformat()}")
        # Log the blocked attempt before aborting
        log_request_info(status_code=429, blocked=True)
        # Send 429 response
        retry_after = int(tracker['blocked_until'] - current_time)
        response = make_response(f"Too Many Requests. Rate limit exceeded. Try again in {retry_after} seconds.", 429)
        response.headers['Retry-After'] = str(retry_after)
        abort(response) # Abort with the custom response

    # --- Check Rate Limit ---
    if current_time - tracker['window_start'] > TIME_WINDOW:
        # Start new window
        tracker['count'] = 1
        tracker['window_start'] = current_time
        print(f"IP {client_ip}: New window started.")
    else:
        # Increment count in current window
        tracker['count'] += 1
        print(f"IP {client_ip}: Request {tracker['count']}/{MAX_REQUESTS} in window.")


    # --- Enforce Rate Limit ---
    if tracker['count'] > MAX_REQUESTS:
        block_expiry_time = current_time + BLOCK_DURATION
        tracker['blocked_until'] = block_expiry_time
        # Reset count and window immediately after blocking
        tracker['count'] = 0
        tracker['window_start'] = 0 # Reset window start as well
        app.logger.warning(f"Rate limit exceeded for IP {client_ip}. Blocking until {datetime.fromtimestamp(block_expiry_time).isoformat()}.")
        print(f"!!! Rate Limit Exceeded !!! IP: {client_ip} blocked for {BLOCK_DURATION} seconds.")
        # Log the request that triggered the block
        log_request_info(status_code=429, blocked=True) # Log it as blocked
        # Send 429 response
        response = make_response(f"Too Many Requests. Rate limit exceeded. Try again in {BLOCK_DURATION} seconds.", 429)
        response.headers['Retry-After'] = str(BLOCK_DURATION)
        abort(response) # Abort with the custom response

    # --- Log Allowed Request (will be logged in after_request if not aborted) ---
    # The actual logging of successful requests happens in after_request
    # to capture the final status code from the view function.
    # However, we can proceed with the request if not blocked or rate-limited.
    return None # Indicate request can proceed to the route handler

# @app.before_request # Keep the original logging function separate if preferred
# def log_request_info(): # Or integrate logging into the rate_limit_and_log above
#     pass # Logic moved or will be handled by after_request

@app.after_request
def log_response_info(response):
    """Log request/response info after the request has been processed."""
    # Avoid logging static file requests here too if desired
    if request.path.startswith('/static'):
        return response

    # Log only if the request wasn't already aborted and logged by before_request
    # Check if the response status code indicates it wasn't blocked (e.g., not 429 from our blocker)
    # Note: This check might be imperfect if routes *legitimately* return 429.
    # A better way might be to set a flag in `g` (Flask's context global) in `before_request`
    # if logging was already done there.
    # For simplicity here, we'll log most responses.
    log_request_info(status_code=response.status_code, blocked=False)
    return response


def log_request_info(status_code, blocked):
    """
    Helper function to log request details to CSV.
    Called by rate_limit_and_log (on block) or after_request (on success/other error).
    """
    ensure_log_dir_exists() # Ensure dir exists every time

    timestamp = datetime.now().isoformat()
    client_ip = request.remote_addr
    src_port = request.environ.get('REMOTE_PORT', 'N/A')
    method = request.method
    path = request.path
    http_body_length = request.content_length if request.content_length is not None else 0
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
        referer,
        status_code,
        blocked
    ]

    try:
        # Update log file path potentially daily
        current_log_file = os.path.join(LOG_DIR, f"requests_{datetime.now().strftime('%Y%m%d')}.csv")
        file_exists = os.path.isfile(current_log_file)
        # Use 'a' mode (append), create if doesn't exist
        with open(current_log_file, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Write header only if file is new or empty
            if not file_exists or os.path.getsize(current_log_file) == 0:
                writer.writerow(LOG_HEADER)
            writer.writerow(log_entry)
    except IOError as e:
        app.logger.error(f"Error writing to request log file {current_log_file}: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error during request logging: {e}")


# --- Removed is_potential_ddos function ---
# The logic is now handled globally in @app.before_request

# --- Placeholder for RFM/Other Logic (Keep as is) ---
def is_ddos_lookup_RFM(client_ip, request_path):
    print(f"RFM Check (Placeholder): Request from {client_ip} to {request_path}")
    # This function is now separate from the primary rate limiting.
    # It could be used for other checks if needed.
    if client_ip == '1.2.3.4': # Example condition different from rate limit
         print("RFM Check: IP matches example condition, flagging.")
         return True
    print("RFM Check: Request deemed not suspicious by this specific check.")
    return False


# --- Routes ---
@app.route('/')
def index():
    # No specific rate limit check needed here, handled by before_request
    return render_template('index.html') # Assuming you have index.html

@app.route('/sensitive-data', strict_slashes=False)
def sensitive_data():
    # The core rate limit check/block is already done by @app.before_request.
    # If the code reaches here, the user is NOT currently rate-limited or blocked.

    client_ip = request.remote_addr # Still useful for logging or other checks

    # You might still want CAPTCHA verification for non-rate-limited users
    # who haven't proven they are human in this session.
    if not session.get('is_human_verified'):
        print(f"IP {client_ip} accessed sensitive data, but not verified this session. Checking other factors or requiring CAPTCHA.")
        # Optional: Add other checks here if needed (e.g., call is_ddos_lookup_RFM)
        if is_ddos_lookup_RFM(client_ip, request.path):
             flash("Suspicious activity detected based on secondary checks.", "warning")
             # Decide action: maybe redirect to CAPTCHA or show limited info
             session['intended_url'] = request.url
             return redirect(url_for('verify_captcha_page'))

        # If no other flags, but not verified, maybe still ask for CAPTCHA first time?
        # Or grant access but log it carefully.
        # For simplicity here, let's grant access if not rate-limited and no other flags.
        # A stricter approach would redirect unverified sessions to CAPTCHA.
        # session['intended_url'] = request.url
        # return redirect(url_for('verify_captcha_page'))
        print(f"IP {client_ip} granted access to sensitive data (not rate-limited, session not verified).")
        return render_template('sensitive_page.html', message="Access granted (session not verified, pass CAPTCHA for full session access).")

    else:
        # User is verified in this session and not rate-limited.
        print(f"IP {client_ip} (verified session) granted access to sensitive data.")
        return render_template('sensitive_page.html', message="Access granted (verified session).")


@app.route('/verify', methods=['GET', 'POST'])
def verify_captcha_page():
    # Rate limiting is handled by before_request. If a user gets here, they aren't blocked.
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        remote_ip = request.remote_addr # Use actual remote_ip for verification
        if not token:
            flash("CAPTCHA verification is required.", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)

        payload = {'secret': RECAPTCHA_SECRET_KEY, 'response': token, 'remoteip': remote_ip}
        try:
            print(f"Sending verification request for IP {remote_ip} to Google.")
            response = requests.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=10) # Increased timeout slightly
            response.raise_for_status() # Check for HTTP errors
            result = response.json()
            print(f"Google verification result for IP {remote_ip}: {result}")
        except requests.exceptions.Timeout:
            app.logger.error(f"CAPTCHA verification request timed out for IP {remote_ip}.")
            flash("Could not verify CAPTCHA: The verification service timed out. Please try again later.", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)
        except requests.exceptions.RequestException as e:
             app.logger.error(f"Error verifying CAPTCHA for IP {remote_ip}: {e}")
             flash(f"Error verifying CAPTCHA: Could not connect to verification service.", "error")
             return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)

        if result.get("success"):
            flash("Verification successful!", "success")
            session['is_human_verified'] = True
            intended_url = session.pop('intended_url', url_for('index'))
            # Prevent redirect loops if intended was verify itself
            if intended_url == url_for('verify_captcha_page'):
                 intended_url = url_for('index')
            # Simple page showing success and link/redirect
            return render_template('verified_ok.html', intended_url=intended_url) # Assuming verified_ok.html
        else:
            error_codes = result.get("error-codes", [])
            app.logger.warning(f"CAPTCHA verification failed for IP {remote_ip}. Errors: {error_codes}")
            flash(f"CAPTCHA verification failed. Please try again. Errors: {', '.join(error_codes)}", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)

    # GET Request
    if not RECAPTCHA_SITE_KEY or "YOUR_RECAPTCHA" in RECAPTCHA_SITE_KEY:
         flash("FATAL ERROR: reCAPTCHA Site Key is not configured!", "error")
         # Log this critical error
         app.logger.critical("RECAPTCHA_SITE_KEY is not configured!")
         return "Server configuration error: reCAPTCHA Site Key missing.", 500

    # Ensure 'intended_url' is in session if redirected here, otherwise default
    if 'intended_url' not in session:
        session['intended_url'] = url_for('index') # Default redirect after verification

    return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)


# --- Main Execution ---
if __name__ == '__main__':
    ensure_log_dir_exists() # Ensure log dir exists on startup
    # Set debug=False for production!
    # Use host='0.0.0.0' to make it accessible on your network
    # Use threaded=True for basic concurrency handling with the in-memory dict,
    # but remember its limitations vs. Redis/Memcached for multi-process workers.
    print(f"Starting Flask App. Rate Limit: {MAX_REQUESTS} req / {TIME_WINDOW} sec. Block Duration: {BLOCK_DURATION} sec.")
    print(f"WARNING: Using in-memory rate limiting. Not suitable for multi-process production setups without external storage (e.g., Redis).")
    if not RECAPTCHA_SITE_KEY or "YOUR_RECAPTCHA" in RECAPTCHA_SITE_KEY or not RECAPTCHA_SECRET_KEY:
         print("\n*** WARNING: reCAPTCHA keys are not configured. CAPTCHA verification will fail. Set RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY environment variables. ***\n")

    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True) # Added threaded=True
