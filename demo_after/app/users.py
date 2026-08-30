"""User management module."""
from app.auth import create_user, login

def register_user(name, email, password):
    user = create_user(name, email, "default_user")
    auth_result = login(name, password)
    return {"user": user, "auth": auth_result}

def get_user_dashboard(user_id):
    return {"user_id": user_id, "dashboard": "active"}
