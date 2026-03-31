import re

TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"drupal", r"sites/default/files"],
    "Joomla": [r"joomla", r"/components/com_"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "React": [r"react(\.min)?\.js", r"__react", r"_reactFiber"],
    "Vue.js": [r"vue(\.min)?\.js", r"__vue__"],
    "Angular": [r"angular(\.min)?\.js", r"ng-version"],
    "Bootstrap": [r"bootstrap(\.min)?\.css", r"bootstrap(\.min)?\.js"],
    "Cloudflare": [r"cloudflare", r"__cf_"],
    "Google Analytics": [r"google-analytics\.com", r"gtag\("],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "nginx": [],  # from headers only
    "Apache": [],  # from headers only
}

HEADER_TECH = {
    "Server": {"nginx": "nginx", "apache": "Apache", "iis": "IIS", "cloudflare": "Cloudflare"},
    "X-Powered-By": {"php": "PHP", "asp.net": "ASP.NET", "express": "Express.js"},
    "X-Generator": {},
    "Via": {"cloudflare": "Cloudflare"},
}


def detect_technologies(http_info: dict):
    headers = http_info.get("response_headers") or {}
    html = http_info.get("html_sample") or ""

    tech = {"from_headers": {}, "from_html": [], "notes": []}

    for hdr_key, patterns in HEADER_TECH.items():
        val = headers.get(hdr_key, "")
        if val:
            tech["from_headers"][hdr_key] = str(val)[:200]
            for keyword, label in patterns.items():
                if keyword in val.lower():
                    tech["notes"].append(f"Detected {label} via {hdr_key} header")

    lower_html = html.lower()
    for name, pats in TECH_PATTERNS.items():
        if not pats:
            continue
        for p in pats:
            if re.search(p, lower_html, flags=re.IGNORECASE):
                tech["from_html"].append(name)
                break

    tech["from_html"] = sorted(list(set(tech["from_html"])))
    return tech
