# CS504 Flask MFA System

This project is a working Flask multi-factor authentication demo using:

- SQLite for user storage
- bcrypt for password hashing
- pyotp for time-based one-time passwords
- QR codes for Microsoft Authenticator and Google Authenticator
- Flask sessions to enforce the login flow

## Pages

1. Register
2. MFA QR code setup
3. Login
4. OTP verification
5. Protected dashboard
6. Logout

## Setup Instructions

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Optional but recommended: set a secret key for Flask sessions:

   ```bash
   export FLASK_SECRET_KEY="replace-with-a-long-random-secret"
   ```

4. Run the app:

   ```bash
   python app.py
   ```

5. Open the app in your browser:

   ```text
   http://127.0.0.1:5000
   ```

## How to Use

1. Go to the register page and create an account.
2. Scan the QR code with Microsoft Authenticator or Google Authenticator.
3. Continue to the login page.
4. Enter your username and password.
5. Enter the 6-digit code from your authenticator app.
6. After successful MFA verification, you will be redirected to the protected dashboard.
7. Use Logout to clear the session.

## Security Notes

- Plaintext passwords are never stored.
- Passwords are stored as bcrypt hashes.
- Each user gets a unique TOTP MFA secret.
- The dashboard requires both a successful password check and successful OTP verification.
- The app uses Flask sessions to track pending MFA and completed MFA.

## Database

The SQLite database is created automatically as `mfa_app.db` when the app starts. It contains one `users` table with:

- `id`
- `username`
- `password_hash`
- `mfa_secret`
- `created_at`

To reset the app during testing, stop the server and delete `mfa_app.db`.
