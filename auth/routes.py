from datetime import datetime
from flask import request, jsonify, redirect, url_for
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
import logging

from auth import auth_bp
from auth.service import create_user, authenticate_user, validate_password
from database.db import db
from database.models import Log

logger = logging.getLogger(__name__)

def audit_log(event):
    try:
        log_entry = Log(event=event)
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Audit log failed: {e}")


# ── API ENDPOINTS ─────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    
    JSON POST data:
        - username (str): Username
        - password (str): Password
        - email (str, optional): Email address
    
    Returns:
        201: User registered successfully
        400: Missing or invalid fields
        409: User already exists
    """
    if current_user.is_authenticated:
        return jsonify({
            "status": "error",
            "code": "ALREADY_AUTHENTICATED",
            "message": "Already logged in. Please logout before registering a new account."
        }), 400
    
    data = request.get_json() or {}
    
    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email", "").strip() or f"{username}@vajrax.local"
    
    if not username or not password:
        return jsonify({
            "status": "error",
            "code": "MISSING_FIELDS",
            "message": "Missing required fields: username, password"
        }), 400
    
    user, error = create_user(username, email, password)
    
    if error:
        audit_log(f"Failed registration: {username} - {error}")
        lowered_error = error.lower()
        if "already registered" in lowered_error:
            status_code = 409
            error_code = "USER_EXISTS"
        elif "valid" in lowered_error or "required" in lowered_error or "must" in lowered_error or "password" in lowered_error:
            status_code = 400
            error_code = "VALIDATION_ERROR"
        else:
            status_code = 400
            error_code = "REGISTRATION_FAILED"
        return jsonify({
            "status": "error",
            "code": error_code,
            "message": error
        }), status_code
    
    login_user(user, remember=False)
    audit_log(f"User registered: {username}")
    
    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and create session.
    
    JSON POST data:
        - username (str): Username
        - password (str): Password
        - remember (bool, optional): Remember login
    
    Returns:
        200: Login successful
        400: Missing credentials
        401: Invalid credentials
    """
    if current_user.is_authenticated:
        return jsonify({
            "status": "info",
            "message": "Already logged in",
            "user": {
                "id": current_user.id,
                "username": current_user.username,
                "role": current_user.role
            }
        }), 200
    
    data = request.get_json() or {}
    
    username = data.get("username", "").strip()
    password = data.get("password", "")
    remember = data.get("remember", False)
    
    if not username or not password:
        return jsonify({
            "status": "error",
            "code": "MISSING_CREDENTIALS",
            "message": "Username and password required"
        }), 400
    
    user = authenticate_user(username, password)
    
    if not user:
        logger.warning(f"Failed login attempt: {username}")
        audit_log(f"Failed login: {username}")
        return jsonify({
            "status": "error",
            "code": "INVALID_CREDENTIALS",
            "message": "Invalid username or password"
        }), 401
    
    login_user(user, remember=remember)
    audit_log(f"Login successful: {username}")
    
    logger.info(f"User logged in: {username}")
    
    return jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Logout current user and destroy session.
    
    Returns:
        200: Logout successful
    """
    username = current_user.username
    logout_user()
    audit_log(f"User logged out: {username}")
    logger.info(f"User logged out: {username}")
    return jsonify({
        "status": "success",
        "message": "Logged out successfully"
    }), 200


@auth_bp.route("/profile", methods=["GET"])
@login_required
def profile():
    """
    Get current user profile.
    
    Returns:
        200: User profile
    """
    audit_log(f"Profile viewed: {current_user.username}")
    return jsonify({
        "status": "success",
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "role": current_user.role,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        }
    }), 200


@auth_bp.route("/change_password", methods=["POST"])
@login_required
def change_password():
    """
    Change password for the currently logged-in user.
    JSON POST data:
        - current_password (str): Current password
        - new_password (str): New password
    """
    data = request.get_json() or {}
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({
            "status": "error",
            "message": "Current and new passwords are required"
        }), 400
        
    is_valid, password_error = validate_password(new_password)
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": password_error
        }), 400

    if not check_password_hash(current_user.password_hash, current_password):
        audit_log(f"Failed password change attempt: {current_user.username}")
        return jsonify({
            "status": "error",
            "message": "Incorrect current password"
        }), 401
        
    try:
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        audit_log(f"Password changed: {current_user.username}")
        return jsonify({
            "status": "success",
            "message": "Password updated successfully"
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error changing password for {current_user.username}: {e}")
        return jsonify({
            "status": "error",
            "message": "Database error - password update failed"
        }), 500