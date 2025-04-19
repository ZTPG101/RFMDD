import time
from collections import defaultdict

# --- Configuration ---
TIME_WINDOW = 60
MAX_REQUESTS = 100 # Reduced for easier testing

# --- Global State (In-memory - limitations apply!) ---
ip_tracker = defaultdict(lambda: {'count': 0, 'window_start': 0})

# --- Function to test ---
def is_potential_ddos(client_ip, request_path):
    """
    Simple traditional DDoS detection based on request rate limiting per IP.
    Checks if a client IP has exceeded MAX_REQUESTS within TIME_WINDOW.
    """
    # Comment out print statements or check they don't interfere with tests
    # print(f"Checking request from {client_ip} to {request_path}")
    current_time = time.time() # We will mock this

    tracker = ip_tracker[client_ip]
    count = tracker['count']
    window_start = tracker['window_start']

    if current_time - window_start > TIME_WINDOW:
        # print(f"Resetting window for IP: {client_ip}")
        ip_tracker[client_ip]['count'] = 1
        ip_tracker[client_ip]['window_start'] = current_time
        # print("Request deemed not suspicious (new window).")
        return False
    else:
        ip_tracker[client_ip]['count'] += 1
        count = ip_tracker[client_ip]['count']

        if count > MAX_REQUESTS:
            # print(f"!!! Potential DDoS detected !!! IP: {client_ip} Count: {count}")
            return True
        else:
            # print(f"IP: {client_ip} Count: {count}/{MAX_REQUESTS} within window.")
            # print("Request deemed not suspicious.")
            return False

# --- Helper function to reset state for tests ---
def reset_tracker():
    """Clears the global ip_tracker."""
    global ip_tracker
    ip_tracker.clear() # Resets the defaultdict
