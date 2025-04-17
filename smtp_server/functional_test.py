
import requests
import os
import time

# Use environment variable for base URL or default to localhost:8000
BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
TEST_EMAIL = "functional-test@example.com"

def test_email_verification_flow():
    """Runs a functional test of the send and verify email endpoints."""
    print(f"--- Running Email Verification Functional Test against {BASE_URL} ---")

    # 1. Send Verification Request
    send_url = f"{BASE_URL}/send-verification"
    payload = {"email": TEST_EMAIL}
    print(f"\n[POST] {send_url} with payload: {payload}")
    try:
        response = requests.post(send_url, json=payload, timeout=10)
        print(f"Status Code: {response.status_code}")
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        data = response.json()
        print(f"Response JSON: {data}")
        assert response.status_code == 202 # Should be Accepted
        assert "Verification email initiated" in data.get("message", "")
    except requests.exceptions.RequestException as e:
        print(f"[FAIL] Request failed: {e}")
        return # Cannot proceed without successful send request
    except Exception as e:
        print(f"[FAIL] Error processing response: {e}")
        return

    # --- IMPORTANT PAUSE ---
    # Since email sending is async, we need to wait for the email to be "sent"
    # and potentially retrieve the token from MailHog if testing full loop.
    # For this simplified test, we assume the token *would* be sent.
    # In a real scenario, you'd need to:
    #   a) Query MailHog's API (usually on port 8025) to find the email and extract the token.
    #   b) Or, if testing against a real SMTP, check the inbox.
    # We will simulate getting the token by querying the DB via another method or skip verification for now.

    print("\n--- Skipping token retrieval and verification step in this basic test ---")
    print("To fully test, you would need to:")
    print("  1. Wait a few seconds.")
    print("  2. Query MailHog API (http://localhost:8025/api/v2/messages) to find the email.")
    print("  3. Extract the verification token from the email body/link.")
    print("  4. Call the GET /verify endpoint with the extracted token.")


    # --- Example: Simulate getting token and verifying (requires MailHog interaction - not implemented here) ---
    # time.sleep(5) # Wait for email
    # try:
    #     mailhog_messages_url = "http://localhost:8025/api/v2/messages"
    #     messages_response = requests.get(mailhog_messages_url)
    #     messages = messages_response.json()
    #     verification_token = None
    #     for msg in messages.get("items", []):
    #         if TEST_EMAIL in msg["To"][0]["Mailbox"] + "@" + msg["To"][0]["Domain"]:
    #             # Crude extraction - find link in body
    #             body = msg["Content"]["Body"]
    #             match = re.search(r"/verify\?token=([a-zA-Z0-9]+)", body)
    #             if match:
    #                 verification_token = match.group(1)
    #                 print(f"\n[INFO] Found token via MailHog: {verification_token[:6]}...")
    #                 break
    #
    #     if not verification_token:
    #         print("[WARN] Could not find verification email/token in MailHog.")
    #         return
    #
    #     # 2. Verify Token
    #     verify_url = f"{BASE_URL}/verify?token={verification_token}"
    #     print(f"\n[GET] {verify_url}")
    #     verify_response = requests.get(verify_url, timeout=10)
    #     print(f"Status Code: {verify_response.status_code}")
    #     verify_response.raise_for_status()
    #     verify_data = verify_response.json()
    #     print(f"Response JSON: {verify_data}")
    #     assert verify_response.status_code == 200
    #     assert f"Email {TEST_EMAIL} has been successfully verified" in verify_data.get("message", "")
    #     print("\n[SUCCESS] Verification successful!")
    #
    # except requests.exceptions.RequestException as e:
    #     print(f"[FAIL] Verification request failed: {e}")
    # except Exception as e:
    #     print(f"[FAIL] Error during verification or MailHog interaction: {e}")

    print("\n--- Email Verification Functional Test Finished ---")

if __name__ == "__main__":
    test_email_verification_flow()

    # Optional: Add RFM functional test
    print("\n--- Running RFM Functional Test ---")
    test_ip = "10.0.0.5" # Use an IP expected from dummy data
    rfm_url = f"{BASE_URL}/rfm/{test_ip}"
    print(f"\n[GET] {rfm_url}")
    try:
        rfm_response = requests.get(rfm_url, timeout=10)
        print(f"Status Code: {rfm_response.status_code}")
        if rfm_response.status_code == 200:
            print("Response JSON:", rfm_response.json())
            print("[SUCCESS] RFM Lookup successful (if data exists).")
        elif rfm_response.status_code == 404:
            print("[INFO] RFM Lookup returned 404 (IP not found, which might be expected if batch job hasn't run/populated this IP).")
        else:
             rfm_response.raise_for_status()
    except requests.exceptions.RequestException as e:
         print(f"[FAIL] RFM request failed: {e}")
