from werkzeug.security import generate_password_hash, check_password_hash
from database.db import db
from database.models import User
import logging

logger = logging.getLogger(__name__)


def create_user(username, email, password, role="operator"):
    """
    Create a new user with validated credentials.
    
    Args:
        username: Unique username
        email: User email address
        password: Plaintext password (will be hashed)
        role: User role (default: operator)
    
    Returns:
        Tuple of (User object, error message) - error is None if successful
    """
    # Validate inputs
    if not username or len(username) < 3:
        return None, "Username must be at least 3 characters"
    
    if not email or '@' not in email:
        return None, "Valid email required"
    
    if not password or len(password) < 6:
        return None, "Password must be at least 6 characters"
    
    # Check for existing user
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    
    if existing_user:
        logger.warning(f"Registration attempt for existing user: {username}")
        return None, "Username or email already registered"
    
    try:
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role=role
        )
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"User created successfully: {username} (role: {role})")
        return user, None
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user {username}: {str(e)}")
        return None, "Database error - user creation failed"


def authenticate_user(username, password):
    """
    Authenticate user with username and password.
    
    Args:
        username: Username
        password: Plaintext password
    
    Returns:
        User object if authentication successful, None otherwise
    """
    if not username or not password:
        return None
    
    try:
        user = User.query.filter_by(username=username).first()
        
        if not user:
            logger.warning(f"Authentication attempt for non-existent user: {username}")
            return None
        
        if check_password_hash(user.password_hash, password):
            logger.info(f"User authenticated successfully: {username}")
            return user
        
        # Legacy support: if stored password is plaintext, allow login once and upgrade hash
        if user.password_hash == password:
            try:
                user.password_hash = generate_password_hash(password)
                db.session.commit()
                logger.info(f"Upgraded plaintext password to hash for user: {username}")
            except Exception as upgrade_error:
                db.session.rollback()
                logger.warning(f"Failed to upgrade legacy password for {username}: {upgrade_error}")
            return user
        
        logger.warning(f"Invalid password attempt for user: {username}")
        return None
    
    except Exception as e:
        logger.error(f"Authentication error for {username}: {str(e)}")
        return None


def get_user_by_id(user_id):
    """
    Retrieve user by ID.
    
    Args:
        user_id: User ID
    
    Returns:
        User object if found, None otherwise
    """
    try:
        return db.session.get(User, user_id)
    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {str(e)}")
        return None


def update_user_role(user_id, new_role):
    """
    Update user role (admin-only operation).
    
    Args:
        user_id: User ID
        new_role: New role value
    
    Returns:
        Tuple of (success boolean, message)
    """
    if new_role not in ["admin", "operator", "analyst"]:
        return False, f"Invalid role: {new_role}"
    
    try:
        user = db.session.get(User, user_id)
        if not user:
            return False, "User not found"
        
        user.role = new_role
        db.session.commit()
        
        logger.info(f"User {user.username} role updated to {new_role}")
        return True, "Role updated successfully"
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user role: {str(e)}")
        return False, "Database error"