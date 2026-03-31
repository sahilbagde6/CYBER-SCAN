"""
Configuration for Securitry.
Reads sensitive values from .env via python-dotenv.
"""

import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    """Base configuration shared across all environments."""

    # Security
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-fallback-change-in-production")
    WTF_CSRF_ENABLED: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # Database
    DB_PATH: str = os.environ.get("DB_PATH", os.path.join(INSTANCE_DIR, "securitry.sqlite3"))

    # Flask internals
    JSON_SORT_KEYS: bool = False

    # Rate limiting
    SCAN_RATE_LIMIT: str = f"{os.environ.get('SCAN_RATE_LIMIT', '12')} per minute"
    DEFAULT_LIMITS: list = ["60 per minute"]

    # HTTP client
    REQUEST_TIMEOUT: tuple = (4, 10)
    MAX_URL_LENGTH: int = 2048
    HTTP_MAX_RETRIES: int = 2

    # Port scanner
    PORT_SCAN_TIMEOUT: float = float(os.environ.get("PORT_SCAN_TIMEOUT", "0.6"))
    PORT_SCAN_WORKERS: int = int(os.environ.get("PORT_SCAN_WORKERS", "100"))
    COMMON_PORTS: dict = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
    }


class DevelopmentConfig(Config):
    DEBUG: bool = True
    SESSION_COOKIE_SECURE: bool = False
    WTF_CSRF_ENABLED: bool = False


class ProductionConfig(Config):
    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = True
    WTF_CSRF_ENABLED: bool = True


class TestingConfig(Config):
    TESTING: bool = True
    WTF_CSRF_ENABLED: bool = False
    DB_PATH: str = ":memory:"


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    """Return the correct config class based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development").lower()
    return config_map.get(env, DevelopmentConfig)
