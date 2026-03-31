"""
HTTP client with timeout, retry logic, and safe HTML sampling.
"""

import logging
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "SecuritryScanner/2.0 (Educational; Authorized Use Only)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Maximum HTML bytes to read for tech fingerprinting (40 KB)
HTML_SAMPLE_BYTES = 40_960


def _make_session(max_retries: int = 2) -> requests.Session:
    """Create a requests.Session with a retry adapter."""
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    return session


def fetch_url(url: str, timeout: tuple = (4, 10), max_retries: int = 2) -> dict:
    """
    Fetch a URL and return a structured dict with response metadata.

    Returns
    -------
    dict with keys:
        final_url, status_code, response_headers,
        elapsed_ms, html_sample, error
    """
    info: dict = {
        "final_url": None,
        "status_code": None,
        "response_headers": {},
        "elapsed_ms": None,
        "html_sample": None,
        "error": None,
    }

    try:
        session = _make_session(max_retries=max_retries)
        start = time.perf_counter()

        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )

        info["final_url"] = response.url
        info["status_code"] = response.status_code
        info["response_headers"] = dict(response.headers)
        info["elapsed_ms"] = int((time.perf_counter() - start) * 1000)

        # Read first 40 KB for fingerprinting — don't load the full page
        chunk = response.raw.read(HTML_SAMPLE_BYTES, decode_content=True)
        try:
            encoding = response.encoding or "utf-8"
            info["html_sample"] = chunk.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            info["html_sample"] = chunk.decode("utf-8", errors="replace")

        log.debug("Fetched %s → %s (%d ms)", url, response.status_code, info["elapsed_ms"])

    except requests.exceptions.Timeout:
        info["error"] = "Request timed out."
        log.warning("Timeout fetching %s", url)
    except requests.exceptions.TooManyRedirects:
        info["error"] = "Too many redirects."
        log.warning("Too many redirects for %s", url)
    except requests.exceptions.SSLError as exc:
        info["error"] = f"SSL error: {exc}"
        log.warning("SSL error for %s: %s", url, exc)
    except requests.exceptions.ConnectionError as exc:
        info["error"] = f"Connection error: {type(exc).__name__}"
        log.warning("Connection error for %s: %s", url, exc)
    except requests.exceptions.RequestException as exc:
        info["error"] = f"Request failed: {type(exc).__name__}"
        log.warning("Request failed for %s: %s", url, exc)
    finally:
        try:
            session.close()
        except Exception:
            pass

    return info
