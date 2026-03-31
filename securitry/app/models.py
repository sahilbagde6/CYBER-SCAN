"""
User model compatible with Flask-Login.
Uses the SQLite storage layer — no SQLAlchemy needed.
"""

from flask_login import UserMixin
from flask import current_app
from .utils.storage import get_user_by_id


class User(UserMixin):
    """Lightweight user object backed by the SQLite users table."""

    def __init__(self, user_row: dict):
        self.id: int = user_row["id"]
        self.username: str = user_row["username"]
        self.email: str = user_row["email"]
        self.password_hash: str = user_row["password"]
        self.created_at: str = user_row["created_at"]

    def get_id(self) -> str:
        """Flask-Login expects a string ID."""
        return str(self.id)

    @staticmethod
    def load(user_id: int) -> "User | None":
        """Load a user from DB by numeric ID. Used by login_manager.user_loader."""
        row = get_user_by_id(current_app.config["DB_PATH"], int(user_id))
        return User(row) if row else None
