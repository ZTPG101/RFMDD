# RFM, Verification & CAPTCHA Service

This project provides a combined API service for:
1.  Looking up pre-calculated RFM scores for IP addresses.
2.  Handling email verification requests.
3.  Protecting specific routes using Google reCAPTCHA v2 based on RFM score analysis.

It includes:
- A FastAPI application (`rfm_api.py`) serving all endpoints.
- A PySpark batch job (`rfm_batch_processor.py`) for RFM calculation (run separately).
- PostgreSQL database managed via SQLAlchemy.
- Docker support (`Dockerfile`, `docker-compose.yml`).
- Unit tests (`test_api.py` - needs updating for CAPTCHA).
- Functional tests (`functional_test.py` - needs updating).
- MailHog integration for email testing.
- Jinja2 templates in the `templates/` directory.

## Setup and Running with Docker (Recommended)

1.  **Prerequisites:** Docker Desktop or Docker Engine/Compose.
2.  **Get reCAPTCHA Keys:** Sign up for Google reCAPTCHA v2 (Checkbox "I'm not a robot") [here](https://www.google.com/recaptcha/admin/create). Add your domain (e.g., `localhost` for testing). You will get a **Site Key** and a **Secret Key**.
3.  **Environment Variables:** Create/update a `.env` file in the project root:

    ```dotenv
    # --- Database ---
    POSTGRES_DB=mydatabase
    POSTGRES_USER=user
    POSTGRES_PASSWORD=your_db_password # Use a strong password!

    # --- pgAdmin ---
    PGADMIN_EMAIL=admin@example.com
    PGADMIN_PASSWORD=your_pgadmin_password # Use a strong password!

    # --- SMTP (Defaults to MailHog) ---
    SMTP_SERVER=mailhog
    SMTP_PORT=1025
    SENDER_EMAIL=noreply@myapp.test
    # SENDER_PASSWORD=

    # --- Application ---
    TOKEN_EXPIRATION_MINUTES=30
    API_PORT=8000
    # Generate using: python -c 'import os; print(os.urandom(24).hex())'
    APP_SECRET_KEY=your_strong_random_session_secret # *** SET THIS ***

    # --- reCAPTCHA v2 ---
    RECAPTCHA_SITE_KEY=your_google_recaptcha_site_key # *** SET THIS ***
    RECAPTCHA_SECRET_KEY=your_google_recaptcha_secret_key # *** SET THIS ***

    # --- RFM Threshold ---
    RFM_COMPOSITE_THRESHOLD=400.0 # Trigger CAPTCHA if score >= this value
    ```

4.  **Build and Run Services:**
    ```bash
    docker-compose up --build
    ```

5.  **Access Services:**
    *   **Web Application / API Docs:** `http://localhost:8000/` / `http://localhost:8000/docs`
    *   **pgAdmin:** `http://localhost:5050` (Connect to `db` service)
    *   **MailHog UI:** `http://localhost:8025`

6.  **Run RFM Batch Job:**
    ```bash
    docker-compose exec app python rfm_batch_processor.py
    ```

7.  **Test Functionality:**
    *   Navigate to `http://localhost:8000/`.
    *   Click the "Access Sensitive Data" link.
    *   If your IP's RFM score (once calculated) is above the threshold (or if no score exists and default behavior triggers), you should be redirected to the `/verify-captcha` page.
    *   Complete the CAPTCHA. On success, you should be redirected back or shown a success message.
    *   Test email verification via the API docs or by integrating it into your frontend.
    *   Check MailHog/pgAdmin as before.

8.  **Stopping:** `docker-compose down` (`-v` to remove volumes).

## Unit/Functional Tests

The provided tests (`test_api.py`, `functional_test.py`) need to be updated to reflect the new CAPTCHA endpoints and session handling.