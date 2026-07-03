from flask import Blueprint
from flask_login import LoginManager

auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/auth"
)

login_manager = LoginManager()
# login_view is set to "login" (HTML page) in app.py after init_app — do NOT set it here
# Setting it to "auth.login" (blueprint) would redirect unauthenticated users to a JSON endpoint
login_manager.login_message = "Authentication required"
login_manager.login_message_category = "warning"

from auth import routes