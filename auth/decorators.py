from functools import wraps
from flask import jsonify, redirect, url_for, request, render_template
from flask_login import current_user

# Role hierarchy — higher index = higher privilege
ROLE_HIERARCHY = {
    'operator': 0,
    'analyst':  1,
    'admin':    2,
}


def _rank(role: str) -> int:
    """Return the numeric rank for a role string (default 0 for unknown)."""
    return ROLE_HIERARCHY.get(role, 0)


def role_required(min_role: str):
    """
    Decorator to enforce role-based access control (hierarchical).

    Example: @role_required('analyst') — allows analyst AND admin,
    but NOT operator.

    Returns 401 if not authenticated, 403 if insufficient permissions.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith('/api/'):
                    return jsonify({
                        "status": "error",
                        "code": "AUTH_REQUIRED",
                        "message": "Authentication required"
                    }), 401
                return redirect(url_for('login'))

            if _rank(current_user.role) < _rank(min_role):
                if request.path.startswith('/api/') or request.headers.get('Accept', '').startswith('application/json'):
                    return jsonify({
                        "status": "error",
                        "code": "INSUFFICIENT_PERMISSIONS",
                        "message": f"This action requires '{min_role}' role or higher"
                    }), 403
                return render_template('error.html', error=f"Insufficient permissions. This action requires '{min_role}' role or higher."), 403

            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


def admin_required(fn):
    """
    Decorator to enforce admin-only access.
    Admins have the highest privilege level.
    """
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({
                    "status": "error",
                    "code": "AUTH_REQUIRED",
                    "message": "Authentication required"
                }), 401
            return redirect(url_for('login'))

        if _rank(current_user.role) < _rank('admin'):
            if request.path.startswith('/api/') or request.headers.get('Accept', '').startswith('application/json'):
                return jsonify({
                    "status": "error",
                    "code": "ADMIN_REQUIRED",
                    "message": "Administrator access required"
                }), 403
            return render_template('error.html', error="Administrator access required"), 403

        return fn(*args, **kwargs)
    return decorated_view


def analyst_required(fn):
    """
    Decorator to enforce analyst-or-higher access.
    Allows both 'analyst' and 'admin' roles.
    """
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith('/api/'):
                return jsonify({
                    "status": "error",
                    "code": "AUTH_REQUIRED",
                    "message": "Authentication required"
                }), 401
            return redirect(url_for('login'))

        if _rank(current_user.role) < _rank('analyst'):
            if request.path.startswith('/api/') or request.headers.get('Accept', '').startswith('application/json'):
                return jsonify({
                    "status": "error",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "message": "Analyst access or higher required"
                }), 403
            return render_template('error.html', error="Analyst access or higher required"), 403

        return fn(*args, **kwargs)
    return decorated_view