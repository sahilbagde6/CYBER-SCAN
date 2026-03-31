"""
Authentication blueprint — login, signup, logout.
Passwords are hashed with werkzeug.security (PBKDF2-SHA256).
"""

import logging
from flask import Blueprint, render_template, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from ..models import User
from ..utils.storage import (
    create_user, get_user_by_email,
    email_exists, username_exists,
)
from ..utils.validators import validate_username, validate_email, validate_password
from ..extensions import limiter

log = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Pages ──────────────────────────────────────────────────────────────────

@bp.get("/login")
def login():
    if current_user.is_authenticated:
        return _redirect_dashboard()
    return render_template("auth/login.html")


@bp.get("/signup")
def signup():
    if current_user.is_authenticated:
        return _redirect_dashboard()
    return render_template("auth/signup.html")


@bp.get("/logout")
@login_required
def logout():
    log.info("User logged out: %s", current_user.username)
    logout_user()
    from flask import redirect, url_for
    return redirect(url_for("auth.login"))


# ── API endpoints ──────────────────────────────────────────────────────────

@bp.post("/api/login")
@limiter.limit("10 per minute")
def api_login():
    """Authenticate a user and start a session."""
    data = request.get_json(silent=True) or {}
    raw_email = (data.get("email") or "").strip()
    raw_password = data.get("password") or ""

    # Validate inputs
    try:
        email = validate_email(raw_email)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    if not raw_password:
        return jsonify({"ok": False, "error": "Password is required."}), 400

    # Look up user
    db = current_app.config["DB_PATH"]
    row = get_user_by_email(db, email)
    if not row or not check_password_hash(row["password"], raw_password):
        log.warning("Failed login attempt for email: %s", email)
        # Use a generic message to avoid user enumeration
        return jsonify({"ok": False, "error": "Invalid email or password."}), 401

    user = User(row)
    login_user(user, remember=bool(data.get("remember")))
    log.info("User logged in: %s", user.username)
    return jsonify({"ok": True, "username": user.username})


@bp.post("/api/signup")
@limiter.limit("5 per minute")
def api_signup():
    """Register a new user account."""
    data = request.get_json(silent=True) or {}
    db = current_app.config["DB_PATH"]

    try:
        username = validate_username(data.get("username") or "")
        email = validate_email(data.get("email") or "")
        password = validate_password(
            data.get("password") or "",
            confirm=data.get("confirm_password"),
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    if email_exists(db, email):
        return jsonify({"ok": False, "error": "Email is already registered."}), 409
    if username_exists(db, username):
        return jsonify({"ok": False, "error": "Username is already taken."}), 409

    password_hash = generate_password_hash(password)
    user_id = create_user(db, username, email, password_hash)

    # Auto-login after signup
    row = {"id": user_id, "username": username, "email": email,
           "password": password_hash, "created_at": ""}
    login_user(User(row))
    log.info("New user registered: %s", username)
    return jsonify({"ok": True, "username": username}), 201


# ── Helpers ────────────────────────────────────────────────────────────────

def _redirect_dashboard():
    from flask import redirect, url_for
    return redirect(url_for("main.dashboard"))
