from flask import Blueprint, request, session, redirect, url_for
from datetime import datetime, timedelta
import bcrypt, secrets

# scripts I made
from db import add_user, get_user_by_username

auth = Blueprint("auth", __name__)

# =====================
# CSRF helpers
# =====================
def _generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

def _validate_csrf_token(token):
    if not token or token != session.get("csrf_token"):
        return False
    return True

# =====================
# Rate limiting helpers
# =====================
failed_logins = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=10)

def _is_locked_out(ip, username):
    key = (ip, username)
    if key not in failed_logins:
        return False
    
    if failed_logins[key]["count"] < MAX_ATTEMPTS:
        return False
    
    if datetime.utcnow() - failed_logins[key]["last_attempt"] > LOCKOUT_TIME:
        failed_logins.pop(key, None)
        return False
    
    return True

def _record_failed_attempt(ip, username):
    key = (ip, username)
    now = datetime.utcnow()
    if key not in failed_logins:
        failed_logins[key] = {"count": 1, "last_attempt": now}
    else:
        failed_logins[key]["count"] += 1
        failed_logins[key]["last_attempt"] = now
        
# =====================
# Registration
# =====================
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not _validate_csrf_token(token):
            return "Invalid CSRF token", 400
        
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        if not username or not password:
            return "Username and password is required", 400
        
        hashed = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
            ).decode("utf-8")
        
        if not add_user(username, hashed):
            return "Username already exists", 400
        
        return "User registered successfully!"
    
    csrf_token = _generate_csrf_token()
    return f"""
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Register</button>
        </form>
    """
    
# =====================
# Login
# =====================
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        
        if not _validate_csrf_token(token):
            return "Invalid CSRF token", 400
        
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            return "Username and password required", 400
        
        ip = request.remote_addr
        
        if _is_locked_out(ip, username):
            return "Too many failed login attempts. Try again later.", 429
        
        user_info = get_user_by_username(username)
        if not user_info:
            _record_failed_attempt(ip, username)
            return "Invalid username or password", 401
        
        user_id, username_db, password_hash, role = user_info
        
        if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
            _record_failed_attempt(ip, username)
            return "Invalid username or password", 401
        
        failed_logins.pop((ip, username), None)
        
        session.clear()
        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username_db
        session["role"] = role
        
        return redirect(url_for("dashboard"))
    
    csrf_token = _generate_csrf_token()
    return f"""
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    """
    
# =====================
# Logout
# =====================
@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
    


