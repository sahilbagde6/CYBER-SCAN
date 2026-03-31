"""
Main blueprint — serves the home page and scan dashboard.
Scan execution is in the api blueprint.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

log = logging.getLogger(__name__)

bp = Blueprint("main", __name__)


@bp.get("/")
def home():
    """Public landing page — redirects to dashboard if already logged in."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


@bp.get("/dashboard")
@login_required
def dashboard():
    """Main scan dashboard — requires authentication."""
    return render_template("dashboard.html", user=current_user)
