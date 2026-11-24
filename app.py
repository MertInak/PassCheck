
import re
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)

# Application configuration
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["SECRET_KEY"] = secrets.token_hex(32)

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Audit logging: never record submitted passwords.
logger = logging.getLogger("passcheck.audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler(LOG_DIR / "audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def audit_event(event, outcome, reason):
    """Record security events without storing password values."""
    logger.info(
        '{"timestamp":"%s","event":"%s","outcome":"%s","reason":"%s"}',
        datetime.now(timezone.utc).isoformat(),
        event,
        outcome,
        reason
    )


# A small demonstration blocklist.
COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123"
}


def analyze_password(password):
    """Evaluate password characteristics without storing the password."""

    if not isinstance(password, str):
        raise ValueError("Password must be text.")

    if not password:
        raise ValueError("Please enter a password.")

    if len(password) > 256:
        raise ValueError("Password exceeds the 256-character limit.")

    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password))
    }

    normalized = password.lower()

    common = normalized in COMMON_PASSWORDS

    predictable = (
        bool(re.fullmatch(r"(password|admin|welcome|qwerty)\d*[!@#$]*",
                          normalized))
        or bool(re.fullmatch(r"(1234|abcd|qwerty)+", normalized))
    )

    score = sum(checks.values())

    if common or predictable:
        score = min(score, 1)

    if len(password) < 8:
        score = min(score, 1)

    if common or predictable:
        strength = "Very Weak"
    elif score <= 1:
        strength = "Very Weak"
    elif score == 2:
        strength = "Weak"
    elif score == 3:
        strength = "Fair"
    elif score == 4:
        strength = "Strong"
    else:
        strength = "Very Strong"

    recommendations = []

    if not checks["length"]:
        recommendations.append("Use at least 12 characters.")

    if not checks["uppercase"]:
        recommendations.append("Include uppercase letters.")

    if not checks["lowercase"]:
        recommendations.append("Include lowercase letters.")

    if not checks["number"]:
        recommendations.append("Include numbers.")

    if not checks["special"]:
        recommendations.append("Include special characters.")

    if common:
        recommendations.append("Avoid commonly used passwords.")

    if predictable:
        recommendations.append("Avoid predictable password patterns.")

    return {
        "strength": strength,
        "score": score,
        "checks": checks,
        "recommendations": recommendations
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        password = request.form.get("password", "")

        try:
            result = analyze_password(password)

            audit_event(
                "password_analysis",
                "success",
                result["strength"]
            )

        except ValueError as exc:
            error = str(exc)
            audit_event(
                "password_analysis",
                "rejected",
                "invalid_input"
            )

        finally:
            # Remove the local reference after analysis.
            password = None

    return render_template(
        "index.html",
        result=result,
        error=error
    )


@app.errorhandler(RequestEntityTooLarge)
def handle_large_request(error):
    audit_event(
        "request_rejected",
        "failure",
        "request_too_large"
    )
    return "Request exceeds the allowed size.", 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
