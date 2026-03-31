"""
Subdomain enumerator — wordlist-based DNS brute-force.
"""

import os
import socket
import logging

log = logging.getLogger(__name__)

_WORDLIST_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "..", "..", "wordlists", "subdomains.txt"
)
_FALLBACK_WORDS = ["www", "api", "dev", "staging", "admin", "mail", "smtp", "vpn", "remote"]


def _load_wordlist(limit: int = 300) -> list[str]:
    """Load subdomain wordlist from disk, fall back to a short default list."""
    try:
        with open(_WORDLIST_PATH, "r", encoding="utf-8") as fh:
            words = [
                line.strip()
                for line in fh
                if line.strip() and not line.startswith("#")
            ]
        log.debug("Loaded %d subdomain words from wordlist", len(words))
        return words[:limit]
    except FileNotFoundError:
        log.warning("Subdomain wordlist not found at %s, using fallback", _WORDLIST_PATH)
        return _FALLBACK_WORDS


def find_subdomains(domain: str, max_results: int = 80) -> list[dict]:
    """
    Resolve candidate subdomains for a root domain using a wordlist.

    Parameters
    ----------
    domain      : str  Target domain (e.g. "example.com").
    max_results : int  Stop after this many confirmed hits.

    Returns
    -------
    List of dicts: [{"subdomain": "www.example.com", "ip": "93.184.216.34"}, ...]
    """
    # Strip to root domain (e.g. sub.example.com → example.com)
    parts = domain.split(".")
    root  = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    words  = _load_wordlist()
    found: list[dict] = []

    log.info("Subdomain enum started: domain=%s words=%d", root, len(words))

    for word in words:
        candidate = f"{word}.{root}"
        try:
            ip = socket.gethostbyname(candidate)
            found.append({"subdomain": candidate, "ip": ip})
            log.debug("Subdomain found: %s → %s", candidate, ip)
            if len(found) >= max_results:
                break
        except socket.gaierror:
            continue
        except Exception as exc:
            log.warning("Unexpected error resolving %s: %s", candidate, exc)
            continue

    log.info("Subdomain enum complete: domain=%s found=%d", root, len(found))
    return found
