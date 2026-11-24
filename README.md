# PassCheck – Password Security Analyzer

## Overview
PassCheck is a Python Flask web application that evaluates password characteristics and provides feedback to help users create stronger passwords. It checks password length, uppercase and lowercase letters, numbers, and special characters. It also identifies a small set of common and predictable passwords.

## Security Controls
- **Input validation:** Rejects empty passwords, non-text input, and passwords exceeding 256 characters.
- **Password privacy:** Does not intentionally store or log submitted password values.
- **Audit logging:** Records analysis outcomes and password-strength classifications without recording the submitted passwords.
- **Request-size limitation:** Limits incoming request data to 16 KB.
- **Output handling:** Uses Flask's Jinja2 templating, which automatically escapes rendered values.
- **Error handling:** Handles oversized requests and invalid input with controlled responses.

## Requirements
- Python 3
- Flask

## Installation and Setup

1. Clone the repository:

   ```powershell
   git clone https://github.com/MertInak/PassCheck.git
   cd PassCheck
   ```

2. Create a virtual environment:

   ```powershell
   python -m venv .venv
   ```

3. Activate the virtual environment:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Start the application:

   ```powershell
   python app.py
   ```

6. Open the application in a browser:

   http://127.0.0.1:5000

## Testing
The application can be manually tested with examples such as:

- `password123` – Expected result: Very Weak.
- `Summer2026` – Expected result: Fair.
- `BlueSky!2026Secure` – Expected result: Very Strong.

Additional negative tests include submitting an empty password and testing input that exceeds the 256-character limit.

## Limitations
PassCheck uses heuristic checks and a small demonstration blocklist. It is an educational demonstration, not a replacement for a production password-strength estimator or a secure authentication system. It does not calculate true password entropy or verify passwords against a comprehensive breach database.

## Repository
https://github.com/MertInak/PassCheck