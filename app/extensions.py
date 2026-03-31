"""
Flask extension singletons.
Initialised in create_app() to avoid circular imports.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# Rate limiter — key function uses real client IP
limiter = Limiter(key_func=get_remote_address)

# Login manager — handles session-based authentication
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# CSRF protection
csrf = CSRFProtect()
