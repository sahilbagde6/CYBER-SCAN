"""
Directory brute-forcer — HTTP path discovery via wordlist.
Uses a persistent session for connection reuse.
"""

import os
import logging
from urllib.parse import urljoin
import requests

log = logging.getLogger(__name__)

_WORDLIST_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "..", "..", "wordlists", "directories.txt"
)
_FALLBACK_WORDS = ["admin", "login", "robots.txt", ".git/", ".env", "sitemap.xml", "api", "backup"]
_INTERESTING_CODES = {200, 204, 301, 302, 401, 403}
_USER_AGENT = "SecuritryScanner/2.0 (Educational; Authorized Use Only)"


def _load_wordlist(limit: int = 400) -> list[str]:
    """Load directory wordlist, fall back to a short default list."""
    try:
        with open(_WORDLIST_PATH, "r", encoding="utf-8") as fh:
            words = [
                line.strip().lstrip("/")
                for line in fh
                if line.strip() and not line.startswith("#")
            ]
        log.debug("Loaded %d directory words", len(words))
        return words[:limit]
    except FileNotFoundError:
        log.warning("Directory wordlist not found, using fallback")
        return _FALLBACK_WORDS


def brute_directories(
    base_url: str,
    max_results: int = 60,
    timeout: tuple = (3, 6),
) -> list[dict]:
    """
    Probe a URL for common directories and files.

    Parameters
    ----------
    base_url    : str    Target base URL (e.g. "https://example.com").
    max_results : int    Stop after this many interesting paths are found.
    timeout     : tuple  (connect_timeout, read_timeout) in seconds.

    Returns
    -------
    List of dicts with interesting paths:
        [{"path": "/admin", "status": 200, "final_url": "https://example.com/admin/"}]
    """
    words   = _load_wordlist()
    results: list[dict] = []

    log.info("Dir brute-force started: target=%s words=%d", base_url, len(words))

    with requests.Session() as session:
        session.headers["User-Agent"] = _USER_AGENT

        for word in words:
            target = urljoin(base_url.rstrip("/") + "/", word)
            try:
                # Use HEAD first for speed — fall back to GET if method not allowed
                resp = session.head(target, timeout=timeout, allow_redirects=True)
                code = resp.status_code

                if code in (405, 403):
                    resp = session.get(target, timeout=timeout, allow_redirects=True)
                    code = resp.status_code

                if code in _INTERESTING_CODES:
                    results.append({"path": "/" + word, "status": code, "final_url": resp.url})
                    log.debug("Dir found: %s → %d", target, code)
                    if len(results) >= max_results:
                        log.info("Dir brute-force hit max_results=%d, stopping early", max_results)
                        break

            except requests.exceptions.Timeout:
                log.debug("Timeout probing %s", target)
            except requests.exceptions.RequestException as exc:
                log.debug("Request error for %s: %s", target, exc)

    log.info("Dir brute-force complete: target=%s found=%d", base_url, len(results))
    return results
