from flask import Blueprint
from flask_login import LoginManager

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/auth"
)

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Authentication required"
login_manager.login_message_category = "warning"

from auth import routes