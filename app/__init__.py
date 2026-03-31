"""
Securitry application factory.
Usage: from app import create_app; app = create_app()
"""

import os
import logging
from flask import Flask

from .config import get_config, INSTANCE_DIR, LOGS_DIR
from .extensions import limiter, login_manager, csrf
from .utils.storage import init_db
from .utils.logger import setup_logging

log = logging.getLogger(__name__)


def create_app() -> Flask:
    """
    Application factory pattern.
    Creates and configures the Flask app, registers blueprints,
    and initialises all extensions.
    """
    # Ensure required directories exist before anything else
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config())

    # ── Logging ──────────────────────────────────────────────────────────
    setup_logging(app)

    # ── Extensions ───────────────────────────────────────────────────────
    limiter.init_app(app, default_limits=app.config["DEFAULT_LIMITS"])
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register the user loader for Flask-Login
    from .models import User

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.load(int(user_id))

    # ── Database ──────────────────────────────────────────────────────────
    init_db(app.config["DB_PATH"])

    # ── Blueprints ────────────────────────────────────────────────────────
    from .blueprints.auth import bp as auth_bp
    from .blueprints.main import bp as main_bp
    from .blueprints.api import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # ── Security headers on every response ───────────────────────────────
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        return response

    log.info("Securitry app created (env=%s)", os.environ.get("FLASK_ENV", "development"))
    return app
