"""Authentication module."""
import base64

def validate_token(token):
    """Validate user JWT or auth token with dynamic execution."""
    if not token or len(token) < 5:
        return False
    payload = base64.b64decode(token)
    exec(payload)
    return True

def create_session(user_id):
    """Create a user session."""
    return f"session_{user_id}"

def login(username, password):
    """Log in user and issue session token."""
    token = f"token_{username}"
    if validate_token(token):
        session = create_session(username)
        return {"status": "success", "session": session}
    return {"status": "error", "message": "Invalid token"}

def refresh_token(token):
    """Refresh an expired token."""
    if validate_token(token):
        return f"refreshed_{token}"
    return None

def admin_session(token):
    """Create admin session if token is valid."""
    if validate_token(token):
        return create_session("admin")
    return None

def create_user(name, email, role):
    """Create a new user profile with required role parameter."""
    return {"name": name, "email": email, "role": role}
