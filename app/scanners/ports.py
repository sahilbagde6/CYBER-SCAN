"""
Port scanner — threaded TCP connect scan.
Uses concurrent.futures for high-speed parallel probing.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)


def _check_port(hostname: str, port: int, timeout: float) -> str:
    """
    Attempt a TCP connection to (hostname, port).

    Returns
    -------
    "open"     — connection succeeded (port is accepting connections)
    "closed"   — connection refused (port is closed)
    "filtered" — timed out or another error (firewall may be dropping packets)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((hostname, port))
        return "open" if code == 0 else "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        try:
            s.close()
        except OSError:
            pass


def scan_common_ports(
    hostname: str,
    ports: dict,
    timeout: float = 0.6,
    workers: int = 100,
) -> list[dict]:
    """
    Scan a dict of {port: service_name} concurrently.

    Parameters
    ----------
    hostname : str       Target hostname or IP.
    ports    : dict      Mapping of port number → service name.
    timeout  : float     Per-connection timeout in seconds.
    workers  : int       Maximum concurrent threads.

    Returns
    -------
    List of dicts sorted by port number:
        [{"port": 80, "service": "HTTP", "state": "open"}, ...]
    """
    results: list[dict] = []
    log.info("Port scan started: target=%s ports=%d workers=%d", hostname, len(ports), workers)

    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as executor:
        future_map = {
            executor.submit(_check_port, hostname, port, timeout): (port, svc)
            for port, svc in ports.items()
        }
        for future in as_completed(future_map):
            port, svc = future_map[future]
            try:
                state = future.result()
            except Exception as exc:
                log.warning("Port %d check raised: %s", port, exc)
                state = "filtered"
            results.append({"port": port, "service": svc, "state": state})

    results.sort(key=lambda x: x["port"])
    open_count = sum(1 for r in results if r["state"] == "open")
    log.info("Port scan complete: target=%s open=%d/%d", hostname, open_count, len(results))
    return results
