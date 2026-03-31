"""
Input validation and SSRF protection helpers.
All public functions raise ValueError with a human-readable message on failure.
"""

import re
import socket
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse

log = logging.getLogger(__name__)

# Username: 3-32 chars, alphanumeric + underscore/hyphen
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")
# Email: simple RFC-compatible check
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
# Password: at least 8 chars
PASSWORD_MIN_LEN = 8


def normalize_and_validate_url(raw: str, max_len: int = 2048) -> tuple[str, str]:
    """
    Validate and normalise a URL string.

    Returns (normalised_url, hostname).
    Raises ValueError with a safe message if the URL is invalid.
    """
    if not raw or not raw.strip():
        raise ValueError("URL is required.")

    raw = raw.strip()

    if len(raw) > max_len:
        raise ValueError("URL is too long.")

    # Auto-prepend scheme if missing
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not parsed.netloc:
        raise ValueError("URL is missing a hostname.")

    if "@" in parsed.netloc:
        raise ValueError("Credentials embedded in URLs are not allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Cannot extract hostname from URL.")

    hn_lower = hostname.lower()
    if hn_lower in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Scanning localhost is not permitted.")

    if hn_lower.endswith(".local") or hn_lower.endswith(".internal"):
        raise ValueError("Scanning .local / .internal domains is not permitted.")

    # Strip fragment, keep everything else
    cleaned = urlunparse(parsed._replace(fragment=""))
    return cleaned, hostname


def ssrf_guard_or_raise(hostname: str) -> None:
    """
    Resolve hostname and block private / reserved IP ranges (SSRF prevention).
    Raises ValueError if the target resolves to a non-routable address.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {exc}") from exc

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ValueError("Resolved to an invalid IP address.") from exc

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            log.warning("SSRF guard blocked: %s → %s", hostname, ip_str)
            raise ValueError(
                "Target resolves to a private or reserved IP address. "
                "Only public internet targets are allowed."
            )


def validate_username(username: str) -> str:
    """Validate and return a cleaned username, or raise ValueError."""
    if not username or not username.strip():
        raise ValueError("Username is required.")
    u = username.strip()
    if not USERNAME_RE.match(u):
        raise ValueError(
            "Username must be 3–32 characters: letters, numbers, _ or -."
        )
    return u


def validate_email(email: str) -> str:
    """Validate and return a lowercase email, or raise ValueError."""
    if not email or not email.strip():
        raise ValueError("Email is required.")
    e = email.strip().lower()
    if not EMAIL_RE.match(e):
        raise ValueError("Invalid email address.")
    if len(e) > 254:
        raise ValueError("Email address is too long.")
    return e


def validate_password(password: str, confirm: str | None = None) -> str:
    """Validate password strength and optional confirmation match."""
    if not password:
        raise ValueError("Password is required.")
    if len(password) < PASSWORD_MIN_LEN:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LEN} characters.")
    if len(password) > 128:
        raise ValueError("Password is too long (max 128 characters).")
    if confirm is not None and password != confirm:
        raise ValueError("Passwords do not match.")
    return password


def sanitize_str(value: str, max_len: int = 500) -> str:
    """Strip whitespace and truncate a string to max_len."""
    return str(value or "").strip()[:max_len]
