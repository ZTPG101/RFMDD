import requests

def simulate_verification(email, base_url="http://localhost:5000"):
    # 1. Send a verification request (simulate user sign-up)
    send_url = f"{base_url}/send-verification"
    payload = {"email": email}
    response = requests.post(send_url, json=payload)
    print("POST /send-verification response:")
    print("Status Code:", response.status_code)
    try:
        data = response.json()
        print("Response JSON:", data)
    except Exception as e:
        print("Failed to decode JSON:", e)
        return

    # Check if the token was provided
    token = data.get("token")
    if not token:
        print("No token received. Exiting simulation.")
        return

    print(f"\nToken received: {token}")

    # 2. Simulate user clicking the verification link
    verify_url = f"{base_url}/verify?token={token}"
    verify_response = requests.get(verify_url)
    print("\nGET /verify response:")
    print("Status Code:", verify_response.status_code)
    print("Response Text:", verify_response.text)

if __name__ == "__main__":
    test_email = "testuser@example.com"  # Replace with your test email address
    simulate_verification(test_email)
