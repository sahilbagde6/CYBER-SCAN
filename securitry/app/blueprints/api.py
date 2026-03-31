"""
API blueprint — all scan endpoints, history, and export.
Rate-limited per-IP to prevent abuse.
"""

import json
import io
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app, send_file, Response
from flask_login import login_required, current_user

from ..extensions import limiter, csrf
from ..utils.validators import normalize_and_validate_url, ssrf_guard_or_raise, sanitize_str
from ..utils.http_client import fetch_url
from ..utils.storage import insert_scan, list_scans, get_scan_by_id

from ..scanners.ip_lookup import resolve_hostname
from ..scanners.headers import analyze_security_headers
from ..scanners.ports import scan_common_ports
from ..scanners.subdomains import find_subdomains
from ..scanners.directories import brute_directories
from ..scanners.tech import detect_technologies

log = logging.getLogger(__name__)

bp = Blueprint("api", __name__, url_prefix="/api")

# CSRF exempt for JSON API endpoints (protected by Login + rate limiting instead)
csrf.exempt(bp)


# ── Scan ───────────────────────────────────────────────────────────────────

@bp.post("/scan")
@login_required
@limiter.limit("12 per minute")
def scan():
    """
    Run a full security scan against a target URL.
    Requires authentication. Rate-limited to 12/min per IP.
    """
    payload = request.get_json(silent=True) or {}
    raw_url = sanitize_str(payload.get("url") or "")

    opts = payload.get("options") or {}
    do_ports      = bool(opts.get("ports", True))
    do_headers    = bool(opts.get("headers", True))
    do_tech       = bool(opts.get("tech", True))
    do_subdomains = bool(opts.get("subdomains", True))
    do_dirs       = bool(opts.get("directories", False))

    # Validate and guard against SSRF
    try:
        url, hostname = normalize_and_validate_url(
            raw_url, max_len=current_app.config["MAX_URL_LENGTH"]
        )
        ssrf_guard_or_raise(hostname)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    started_at = datetime.utcnow().isoformat() + "Z"
    log.info("Scan started by user=%s target=%s", current_user.id, hostname)

    # ── Run scanners ────────────────────────────────────────────────────
    cfg = current_app.config
    http_info   = fetch_url(url, timeout=cfg["REQUEST_TIMEOUT"], max_retries=cfg["HTTP_MAX_RETRIES"])
    ip_info     = resolve_hostname(hostname)
    header_info = analyze_security_headers(http_info) if do_headers else {"enabled": False}
    tech_info   = detect_technologies(http_info)      if do_tech    else {"enabled": False}

    ports_info = (
        scan_common_ports(
            hostname=hostname,
            ports=cfg["COMMON_PORTS"],
            timeout=cfg["PORT_SCAN_TIMEOUT"],
            workers=cfg["PORT_SCAN_WORKERS"],
        )
        if do_ports else {"enabled": False}
    )

    subdomain_info = find_subdomains(hostname) if do_subdomains else {"enabled": False}
    directory_info = brute_directories(url)   if do_dirs       else {"enabled": False}

    # ── Risk scoring ─────────────────────────────────────────────────────
    hints, score = [], 100

    if do_headers and isinstance(header_info, dict) and header_info.get("missing"):
        miss = len(header_info["missing"])
        score -= min(45, miss * 8)
        for h in header_info["missing"]:
            hints.append(f"Missing security header: {h}")

    risky_ports = {21, 23, 445, 3306, 5432, 6379, 27017}
    if do_ports and isinstance(ports_info, list):
        open_risky = [p for p in ports_info if p["state"] == "open" and p["port"] in risky_ports]
        if open_risky:
            names = ", ".join(p["service"] for p in open_risky)
            score -= min(35, len(open_risky) * 10)
            hints.append(f"Risky ports open: {names} — review firewall rules.")

    server = (http_info.get("response_headers") or {}).get("Server")
    if server:
        hints.append(f"Server banner exposed: {server}")

    if http_info.get("error"):
        hints.append(f"HTTP fetch error: {http_info['error']}")

    score = max(0, min(100, score))
    risk_level = "LOW" if score >= 80 else "MEDIUM" if score >= 50 else "HIGH"

    result = {
        "ok": True,
        "target":     {"url": url, "hostname": hostname, "started_at": started_at},
        "http":       http_info,
        "ip":         ip_info,
        "headers":    header_info,
        "ports":      ports_info,
        "tech":       tech_info,
        "subdomains": subdomain_info,
        "directories":directory_info,
        "risk":       {"score": score, "level": risk_level, "hints": hints[:30]},
    }

    insert_scan(current_app.config["DB_PATH"], result, user_id=current_user.id)
    log.info("Scan complete user=%s target=%s risk=%s score=%d",
             current_user.id, hostname, risk_level, score)
    return jsonify(result)


# ── History ─────────────────────────────────────────────────────────────────

@bp.get("/history")
@login_required
def history():
    """Return the current user's scan history."""
    limit = min(int(request.args.get("limit", 20)), 100)
    items = list_scans(current_app.config["DB_PATH"], limit=limit, user_id=current_user.id)
    return jsonify({"ok": True, "items": items})


# ── Export ───────────────────────────────────────────────────────────────────

@bp.get("/export/<int:scan_id>/json")
@login_required
def export_json(scan_id: int):
    """Export a scan result as a downloadable JSON file."""
    row = get_scan_by_id(current_app.config["DB_PATH"], scan_id)
    if not row:
        return jsonify({"ok": False, "error": "Scan not found."}), 404

    payload = json.dumps(row["result"], indent=2)
    buf = io.BytesIO(payload.encode("utf-8"))
    filename = f"scan_{scan_id}_{row['hostname']}.json"
    return send_file(buf, mimetype="application/json",
                     as_attachment=True, download_name=filename)


@bp.get("/export/<int:scan_id>/pdf")
@login_required
def export_pdf(scan_id: int):
    """Export a scan result as a formatted PDF report."""
    row = get_scan_by_id(current_app.config["DB_PATH"], scan_id)
    if not row:
        return jsonify({"ok": False, "error": "Scan not found."}), 404

    try:
        pdf_bytes = _build_pdf(row)
        buf = io.BytesIO(pdf_bytes)
        filename = f"securitry_report_{scan_id}_{row['hostname']}.pdf"
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except Exception as exc:
        log.error("PDF generation failed for scan %d: %s", scan_id, exc)
        return jsonify({"ok": False, "error": "PDF generation failed."}), 500


def _build_pdf(row: dict) -> bytes:
    """Build a simple PDF report using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_LEFT

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    result = row["result"]
    risk = result.get("risk", {})
    target = result.get("target", {})

    DARK  = colors.HexColor("#050a0f")
    CYAN  = colors.HexColor("#00d4ff")
    GREEN = colors.HexColor("#00ff88")
    RED   = colors.HexColor("#ff3860")
    WARN  = colors.HexColor("#ffb800")
    GREY  = colors.HexColor("#4a7a9b")

    risk_color = {"LOW": GREEN, "MEDIUM": WARN, "HIGH": RED}.get(risk.get("level", ""), GREY)

    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=CYAN, fontSize=18, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=CYAN, fontSize=12, spaceBefore=14, spaceAfter=4)
    normal = ParagraphStyle("n", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#c8e6f5"))
    mono = ParagraphStyle("m", parent=styles["Code"], fontSize=8, textColor=GREY)

    story = [
        Paragraph("SECURITRY — Security Scan Report", h1),
        Paragraph(f"Target: <b>{target.get('hostname', '')}</b>", normal),
        Paragraph(f"URL: {target.get('url', '')}", mono),
        Paragraph(f"Scanned: {row.get('created_at', '')}", mono),
        Spacer(1, 0.3*cm),
        Paragraph(f"Risk Level: <b>{risk.get('level', '—')}</b>  |  Score: {risk.get('score', '—')}/100", h2),
    ]

    if risk.get("hints"):
        story.append(Paragraph("Findings", h2))
        for h in risk["hints"]:
            story.append(Paragraph(f"• {h}", normal))

    # Ports table
    ports = result.get("ports")
    if isinstance(ports, list) and ports:
        story.append(Paragraph("Port Scan", h2))
        data = [["Port", "Service", "State"]]
        for p in ports:
            data.append([str(p["port"]), p["service"], p["state"].upper()])
        t = Table(data, colWidths=[2*cm, 5*cm, 3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), CYAN),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0d1a26"), colors.HexColor("#0c1624")]),
            ("TEXTCOLOR",  (0,1), (-1,-1), colors.HexColor("#c8e6f5")),
            ("GRID",       (0,0), (-1,-1), 0.25, GREY),
        ]))
        story.append(t)

    # Headers
    headers = result.get("headers", {})
    if isinstance(headers, dict) and headers.get("details"):
        story.append(Paragraph("Security Headers", h2))
        data = [["Header", "Present", "Note"]]
        for d in headers["details"]:
            data.append([d["header"], "✓" if d["present"] else "✗", d["why"]])
        t = Table(data, colWidths=[6*cm, 1.5*cm, 9*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), CYAN),
            ("FONTSIZE",   (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0d1a26"), colors.HexColor("#0c1624")]),
            ("TEXTCOLOR",  (0,1), (-1,-1), colors.HexColor("#c8e6f5")),
            ("GRID",       (0,0), (-1,-1), 0.25, GREY),
        ]))
        story.append(t)

    doc.build(story)
    return buf.getvalue()
