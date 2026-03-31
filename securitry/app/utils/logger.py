"""
Centralised logging setup for Securitry.
Call setup_logging(app) inside create_app().
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(app):
    """Configure file + console logging for the Flask app."""
    from app.config import LOGS_DIR
    os.makedirs(LOGS_DIR, exist_ok=True)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler — 5 MB per file, keep 3 backups
    fh = RotatingFileHandler(
        os.path.join(LOGS_DIR, "securitry.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if app.debug else logging.WARNING)
    ch.setFormatter(fmt)

    app.logger.setLevel(logging.DEBUG)
    app.logger.addHandler(fh)
    app.logger.addHandler(ch)

    # Suppress noisy werkzeug logs in production
    if not app.debug:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app.logger.info("Logging initialised.")
