# simulate_attack.py
import time
import random
import sys

# --- Import the logic to test ---
# Ensure ddos_detector.py is in the same directory or Python path
try:
    from ddos_detector import (
        is_potential_ddos,
        reset_tracker,
        MAX_REQUESTS,
        TIME_WINDOW,
        ip_tracker # Import to inspect state (optional)
    )
except ImportError:
    print("Error: Could not import from ddos_detector.py.")
    print("Make sure ddos_detector.py is in the same directory.")
    sys.exit(1)

# --- Simulation Configuration ---
ATTACKER_IP = "192.0.2.100"  # A typical fake attacker IP
LEGIT_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "203.0.113.5",
]
# Number of requests to send in the initial burst (more than MAX_REQUESTS)
TOTAL_REQUESTS_BURST = MAX_REQUESTS + 50
# How often to mix in a legitimate request (1 / MIX_IN_LEGIT_EVERY)
MIX_IN_LEGIT_EVERY = 10
# Delay between simulated requests (seconds). Use 0 for max speed.
DELAY_BETWEEN_REQUESTS = 0.01 # Lower value = faster simulation = quicker trigger

# --- Simulation ---

def run_simulation():
    print("--- Starting DDoS Simulation ---")
    print(f"Target Module: ddos_detector.py")
    print(f"Rate Limit: {MAX_REQUESTS} requests / {TIME_WINDOW} seconds")
    print(f"Attacker IP: {ATTACKER_IP}")
    print(f"Legitimate IPs: {LEGIT_IPS}")
    print(f"Simulating {TOTAL_REQUESTS_BURST} requests with ~{DELAY_BETWEEN_REQUESTS*1000:.1f} ms delay...")
    print("-" * 30)

    # Reset state before starting
    reset_tracker()
    start_sim_time = time.monotonic() # Use monotonic clock for measuring sim duration

    flagged_count = 0
    attacker_requests_sent = 0

    for i in range(TOTAL_REQUESTS_BURST):
        # Decide which IP to use for this request
        if (i + 1) % MIX_IN_LEGIT_EVERY == 0 and LEGIT_IPS:
            current_ip = random.choice(LEGIT_IPS)
            source = "Legit"
        else:
            current_ip = ATTACKER_IP
            source = "Attacker"
            attacker_requests_sent += 1

        # Simulate a request path
        request_path = f"/resource/{random.randint(1, 100)}"

        # --- Call the actual detection logic ---
        is_flagged = is_potential_ddos(current_ip, request_path)
        # ----------------------------------------

        status = "FLAGGED (Potential DDoS)" if is_flagged else "Allowed"
        if is_flagged and current_ip == ATTACKER_IP:
            flagged_count += 1

        # Optional: More detailed logging for attacker
        attacker_info = ""
        if current_ip == ATTACKER_IP:
           # Accessing global ip_tracker - be aware if you change implementation
           current_count = ip_tracker.get(ATTACKER_IP, {}).get('count', 0)
           attacker_info = f" (Attacker Count: {current_count})"


        print(f"Req {i+1:>4} | Source: {source:<8} | IP: {current_ip:<15} | Status: {status:<24}{attacker_info}")

        # Introduce delay
        if DELAY_BETWEEN_REQUESTS > 0:
            time.sleep(DELAY_BETWEEN_REQUESTS)

        # Optional: Early exit if clearly triggered
        # if flagged_count > 5 and current_ip == ATTACKER_IP:
        #    print("\nAttacker consistently flagged, shortening burst...")
        #    break # Stop burst early if desired

    end_sim_time = time.monotonic()
    print("-" * 30)
    print(f"--- Burst Finished ({end_sim_time - start_sim_time:.2f} seconds) ---")
    print(f"Attacker ({ATTACKER_IP}) requests sent: {attacker_requests_sent}")
    print(f"Attacker requests flagged: {flagged_count}")
    # Print final counts from the tracker
    print("\nFinal counts in tracker (sample):")
    if ATTACKER_IP in ip_tracker:
        print(f" - {ATTACKER_IP}: {ip_tracker[ATTACKER_IP]['count']}")
    for lip in LEGIT_IPS[:2]: # Show first few legit IPs
         if lip in ip_tracker:
             print(f" - {lip}: {ip_tracker[lip]['count']}")
    print("-" * 30)


    # --- Test Window Reset ---
    wait_time = TIME_WINDOW + 2
    print(f"\n--- Waiting for TIME_WINDOW to expire ({wait_time} seconds)... ---")
    time.sleep(wait_time)

    print("\n--- Sending requests after window expiry ---")

    # Attacker should be allowed again initially because the window reset
    print("\nTesting attacker IP again (should be allowed initially):")
    for i in range(3):
        path = f"/after_wait/attacker/{i}"
        is_flagged = is_potential_ddos(ATTACKER_IP, path)
        status = "FLAGGED" if is_flagged else "Allowed"
        current_count = ip_tracker.get(ATTACKER_IP, {}).get('count', 0)
        print(f"Request: IP={ATTACKER_IP:<15} | Status: {status:<24} (Count: {current_count})")
        time.sleep(DELAY_BETWEEN_REQUESTS)

    # Legitimate IPs should also be fine
    if LEGIT_IPS:
        print("\nTesting legitimate IP again:")
        legit_ip_test = LEGIT_IPS[0]
        for i in range(3):
            path = f"/after_wait/legit/{i}"
            is_flagged = is_potential_ddos(legit_ip_test, path)
            status = "FLAGGED" if is_flagged else "Allowed"
            current_count = ip_tracker.get(legit_ip_test, {}).get('count', 0)
            print(f"Request: IP={legit_ip_test:<15} | Status: {status:<24} (Count: {current_count})")
            time.sleep(DELAY_BETWEEN_REQUESTS)

    print("\n--- Simulation Complete ---")

if __name__ == "__main__":
    run_simulation()
