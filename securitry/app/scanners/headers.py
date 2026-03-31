SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS by restricting content sources.",
    "X-Frame-Options": "Prevents clickjacking (iframe embedding).",
    "X-Content-Type-Options": "Prevents MIME sniffing (nosniff).",
    "Strict-Transport-Security": "Forces HTTPS (HSTS).",
    "Referrer-Policy": "Controls referrer leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
    "Cross-Origin-Opener-Policy": "Helps isolate browsing context.",
}


def analyze_security_headers(http_info: dict):
    headers = http_info.get("response_headers") or {}
    present, missing, details = [], [], []
    for h, why in SECURITY_HEADERS.items():
        if h in headers:
            present.append(h)
            details.append({"header": h, "present": True, "value": str(headers.get(h))[:200], "why": why})
        else:
            missing.append(h)
            details.append({"header": h, "present": False, "value": None, "why": why})
    return {"present": present, "missing": missing, "details": details}
