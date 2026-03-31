# SECURITRY v2 — Web Security Toolkit

> ⚠️ **For authorized use only.** Only scan systems you own or have explicit permission to test.

A production-grade Flask security reconnaissance toolkit with a cyberpunk UI, user authentication, scan history, and PDF/JSON export.

---

## What's New in v2

| Area | Changes |
|---|---|
| **Security** | Password hashing (PBKDF2-SHA256), Flask-Login sessions, CSRF protection, security headers on every response, SSRF guard |
| **Auth** | Full login / signup / logout with real session management |
| **Config** | dotenv support — secrets live in `.env`, never in code; Dev/Prod/Testing config classes |
| **API** | New `/api` blueprint with `/api/scan`, `/api/history`, `/api/export/<id>/json`, `/api/export/<id>/pdf` |
| **Database** | Users table added; scans linked to user IDs |
| **Logging** | Rotating file logger (`logs/securitry.log`) + console |
| **HTTP client** | Retry adapter (urllib3), structured error types, 40 KB HTML sampling |
| **Scanners** | Full docstrings, structured logging, improved error handling |
| **Frontend** | Animated neon-grid canvas, shimmer auth card, export buttons, stat pills, password visibility toggle |
| **Cleanup** | `.gitignore`, `.env.example`, no `__pycache__` in repo |

---

## Quick Start

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and set a strong SECRET_KEY

# 4. Run
python run.py
# Open http://127.0.0.1:5000
```

---

## Project Structure

```
securitry/
├── .env.example            ← copy to .env and configure
├── .gitignore
├── run.py                  ← entry point
├── requirements.txt
│
├── wordlists/
│   ├── subdomains.txt
│   └── directories.txt
│
├── logs/                   ← auto-created, rotating log files
├── instance/               ← auto-created, SQLite database
│
└── app/
    ├── __init__.py         ← app factory (create_app)
    ├── config.py           ← Dev / Prod / Testing config classes
    ├── extensions.py       ← Flask-Limiter, Flask-Login, CSRF
    ├── models.py           ← User model (Flask-Login compatible)
    │
    ├── blueprints/
    │   ├── auth.py         ← /auth/login, /auth/signup, /auth/logout
    │   │                      /auth/api/login, /auth/api/signup
    │   ├── main.py         ← / (landing), /dashboard
    │   └── api.py          ← /api/scan, /api/history
    │                          /api/export/<id>/json|pdf
    │
    ├── scanners/
    │   ├── ip_lookup.py    ← DNS resolution
    │   ├── ports.py        ← threaded TCP port scan
    │   ├── headers.py      ← HTTP security header analysis
    │   ├── tech.py         ← technology fingerprinting
    │   ├── subdomains.py   ← DNS wordlist brute-force
    │   └── directories.py  ← HTTP path discovery
    │
    ├── utils/
    │   ├── validators.py   ← URL/email/password validation, SSRF guard
    │   ├── http_client.py  ← requests session with retry adapter
    │   ├── storage.py      ← SQLite: users + scans tables
    │   └── logger.py       ← rotating file + console logging setup
    │
    ├── static/
    │   ├── css/app.css     ← full cyberpunk theme
    │   └── js/
    │       ├── bg.js       ← animated neon grid + particle canvas
    │       ├── app.js      ← shared utils (loader, esc, history)
    │       └── scanner.js  ← scan form + result renderer + export
    │
    └── templates/
        ├── base.html       ← nav (auth-aware), loader, scanlines
        ├── index.html      ← public landing with feature grid
        ├── dashboard.html  ← scan console (login required)
        └── auth/
            ├── login.html
            └── signup.html
```

---

## API Reference

### POST `/api/scan`
Requires login. Rate-limited to 12/min per IP.
```json
{
  "url": "https://example.com",
  "options": {
    "ports": true,
    "headers": true,
    "tech": true,
    "subdomains": true,
    "directories": false
  }
}
```

### GET `/api/history?limit=20`
Returns the current user's scan history summaries.

### GET `/api/export/<scan_id>/json`
Download a scan result as JSON.

### GET `/api/export/<scan_id>/pdf`
Download a formatted PDF report.

### POST `/auth/api/login`
```json
{ "email": "...", "password": "...", "remember": false }
```

### POST `/auth/api/signup`
```json
{ "username": "...", "email": "...", "password": "...", "confirm_password": "..." }
```

---

## Security Notes

- Passwords hashed with PBKDF2-SHA256 via `werkzeug.security`
- SSRF guard blocks private/loopback/reserved IPs
- Rate limiting: 12 scans/min, 10 logins/min, 5 signups/min
- CSRF protection enabled (disabled in dev for easy API testing)
- `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` added to every response
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` in production
