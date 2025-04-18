from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import os # For a secure session key
import time
from collections import defaultdict

app = Flask(__name__)

# --- Configuration ---
# IMPORTANT: Set a strong secret key for Flask sessions!
# You can generate one using: python -c 'import os; print(os.urandom(16))'
app.secret_key = b'c3eea4e72ec11981e2c48798c13f634679b7c955433ae647' # Replace with YOUR generated key

# Replace with your actual reCAPTCHA keys from Google Admin Console
RECAPTCHA_SITE_KEY = "6LcvnhorAAAAACkm2jzB1gGUvDkHgFGrHbRDi5R6"  # Used in HTML
RECAPTCHA_SECRET_KEY = "6LcvnhorAAAAAN8BYM_6Bklvojrtrm9eOxhcHV2b" # Used for server-side verification
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

TIME_WINDOW = 60
MAX_REQUESTS = 100
# --- Global State (In-memory - limitations apply!) ---
# Dictionary to store request counts and window start time per IP
# Format: ip_tracker[client_ip] = {'count': N, 'window_start': timestamp}
ip_tracker = defaultdict(lambda: {'count': 0, 'window_start': 0})
# --- DDoS Rate Limiting Placeholder ---
def is_potential_ddos(client_ip, request_path):
    """
    Simple traditional DDoS detection based on request rate limiting per IP.

    Checks if a client IP has exceeded MAX_REQUESTS within TIME_WINDOW.

    Args:
        client_ip (str): The IP address of the client making the request.
        request_path (str): The path being requested (optional, used for logging here).

    Returns:
        bool: True if the request rate exceeds the limit (potential DDoS), False otherwise.
    """
    print(f"Checking request from {client_ip} to {request_path}")
    current_time = time.time()

    # Get tracking info for this IP
    tracker = ip_tracker[client_ip]
    count = tracker['count']
    window_start = tracker['window_start']

    # Check if the time window has expired
    if current_time - window_start > TIME_WINDOW:
        # Reset the count and window start time for this IP
        print(f"Resetting window for IP: {client_ip}")
        ip_tracker[client_ip]['count'] = 1
        ip_tracker[client_ip]['window_start'] = current_time
        print("Request deemed not suspicious (new window).")
        return False
    else:
        # Increment the request count within the current window
        ip_tracker[client_ip]['count'] += 1
        count = ip_tracker[client_ip]['count'] # get updated count

        # Check if the count exceeds the maximum allowed requests
        if count > MAX_REQUESTS:
            print(f"!!! Potential DDoS detected !!! IP: {client_ip} exceeded {MAX_REQUESTS} requests in {TIME_WINDOW}s (Count: {count})")
            # Optional: You might want to avoid resetting the window immediately
            # if you are blocking, so subsequent requests are also caught quickly.
            # However, for just detection/flagging, this check is sufficient.
            return True # Flag as suspicious
        else:
            # Request is within limits for the current window
            # print(f"IP: {client_ip} Count: {count}/{MAX_REQUESTS} within window.")
            print("Request deemed not suspicious.")
            return False

def reset_tracker():
    """Clears the global ip_tracker."""
    global ip_tracker
    ip_tracker.clear() # Resets the defaultdict

# --- Your DDoS/RFM Logic Placeholder ---
def is_ddos_lookup_RFM(client_ip, request_path):
    """
    Placeholder for your DDoS detection logic.
    Replace this with your actual database lookup and RFM scoring.
    Return True if the request is suspicious, False otherwise.
    """
    print(f"Checking request from {client_ip} to {request_path}")
    # --- !!! START: Replace with your real logic !!! ---
    # Example: Check request frequency from this IP in your DB
    # Example: Check if IP is on a known bad list
    # Example: Analyze RFM score (Recency/Frequency/Monetary or Maliciousness?)
    # For demonstration, let's trigger CAPTCHA sometimes (e.g., based on IP)
    if client_ip == '127.0.0.1': # Just an example trigger condition
         # Look up in DB, calculate score etc.
         print("IP matches example condition, flagging as potential DDoS.")
         return True # Flag as suspicious
    # --- !!! END: Replace with your real logic !!! ---
    print("Request deemed not suspicious.")
    return False

# --- Routes ---
@app.route('/')
def index():
    """Simple landing page."""
    return render_template('index.html')

@app.route('/sensitive-data')
def sensitive_data():
    """This is the route we want to protect."""
    client_ip = request.remote_addr

    # 1. Check if user is already verified in this session
    if session.get('is_human_verified'):
        print("User already verified in this session.")
        return render_template('sensitive_page.html', message="Access granted (already verified).")

    # 2. Perform your DDoS/suspicion check
    if is_potential_ddos(client_ip, request.path):
        print("Potential DDoS detected. Redirecting to CAPTCHA.")
        # Store the URL they were trying to access so we can redirect later
        session['intended_url'] = request.url
        return redirect(url_for('verify_captcha_page'))
    else:
        # Not suspicious, but not verified yet either.
        # You might grant access here OR still force verification once per session.
        # For simplicity here, let's grant access if not flagged.
        # If you *always* want verification before accessing, remove this else
        # and always redirect if not session.get('is_human_verified')
        print("Not suspicious, granting access for this request.")
        return render_template('sensitive_page.html', message="Access granted (not flagged as suspicious).")


@app.route('/verify', methods=['GET', 'POST'])
def verify_captcha_page():
    """Displays the CAPTCHA page and handles the verification."""
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        remote_ip = request.remote_addr

        if not token:
            flash("CAPTCHA verification is required.", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)

        # Server-side verification with Google
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token,
            'remoteip': remote_ip # Optional, but recommended
        }
        try:
            response = requests.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=5)
            response.raise_for_status() # Raise an exception for bad status codes
            result = response.json()
        except requests.exceptions.RequestException as e:
             flash(f"Error verifying CAPTCHA: {e}", "error")
             return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)


        print(f"Google verification result: {result}")

        if result.get("success"):
             # --- Verification Successful ---
            flash("Verification successful!", "success")
            session['is_human_verified'] = True # Mark session as verified

            # Redirect to the originally intended URL, or fallback to index
            intended_url = session.pop('intended_url', url_for('index'))
            # return redirect(intended_url)
            # Or just show a success page for clarity in demo:
            return render_template('verified_ok.html', intended_url=intended_url)

        else:
            # --- Verification Failed ---
            error_codes = result.get("error-codes", [])
            flash(f"CAPTCHA verification failed. Please try again. Errors: {error_codes}", "error")
            return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)

    # --- GET Request: Just show the CAPTCHA form ---
    # Ensure site key is passed correctly
    if not RECAPTCHA_SITE_KEY or "YOUR_RECAPTCHA" in RECAPTCHA_SITE_KEY:
         flash("FATAL ERROR: reCAPTCHA Site Key is not configured in app.py!", "error")
         # Avoid rendering the broken captcha - show an error message instead
         return "Server configuration error: reCAPTCHA Site Key missing.", 500

    return render_template('verify_captcha.html', site_key=RECAPTCHA_SITE_KEY)


if __name__ == '__main__':
    # Make sure debug=False in production!
    app.run(debug=True, host='0.0.0.0', port=5000) # Listen on all interfaces for testing
