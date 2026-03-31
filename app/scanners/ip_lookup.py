import socket


def resolve_hostname(hostname: str):
    out = {"hostname": hostname, "ip": None, "error": None}
    try:
        out["ip"] = socket.gethostbyname(hostname)
    except Exception as e:
        out["error"] = f"DNS resolve failed: {type(e).__name__}"
    return out
