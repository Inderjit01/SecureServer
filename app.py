# -*- coding: utf-8 -*-
"""
Created on Sat Jan 31 11:47:16 2026

@author: inder
"""

from flask import Flask, request, session, redirect, url_for
from functools import wraps
from datetime import datetime, timedelta
import bcrypt, secrets
# Classes I made
from config import Config
from db import init_db, add_user, get_user_by_username

app = Flask(__name__)
app.config.from_object(Config)

failed_logins = {}

MAX_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=10)

init_db()

# Check if user made too many attempts to login and resets attempts if time has passed
def _is_locked_out(ip, username):
    key = (ip, username)
    if key not in failed_logins:
        return False
    
    record = failed_logins[key]
    if record["count"] < MAX_ATTEMPTS:
        return False
    
    if datetime.utcnow() - record["last_attempt"] > LOCKOUT_TIME:
        del failed_logins[key]
        return False
    
    return True

# Updates FAILED_LOGINS
def _record_failed_attempt(ip, username):
    key = (ip, username)
    now = datetime.utcnow()
    
    if key not in failed_logins:
        failed_logins[key] = {"count": 1, "last_attempt": now}
    else:
        failed_logins[key]["count"] += 1
        failed_logins[key]["last_attempt"] = now
        
def _generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]
        
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return "Access denied: Admins only", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    return "Hello, world!"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return "Invaild CSRF token", 400
        
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            return "Username and password required", 400
        
        hashed = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")
        
        if not add_user(username, hashed):
            return "Username already exists", 400
        
        return "User registered successfully"
    
    csrf_token = _generate_csrf_token()
    return """
        <form method="POST">
            <input type="hidden" name="csrf_token" value=f"{csrf_token}">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Register</button>
        </form>
    """
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # make sure user fills in both username and password
        if not username or not password:
            return "Username and password required", 400
        
        # Check is user made too many login attempts
        ip = request.remote_addr
        if _is_locked_out(ip, username):
            return "Too many failed attempts. Try again later.", 429

        # makes sure the username exists in the database        
        user_info = get_user_by_username(username)
        if not user_info:
            _record_failed_attempt(ip, username)
            return "Username or password incorrect", 401
        
        user_id, un, password_hash, role = user_info
        
        # checks the password the user is trying to login with to the password stored in the db
        if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
            _record_failed_attempt(ip, username)
            return "Username or password incorrect", 401
        
        # saves the user_id to the flask session method
        session.clear()
        session.permanent = True # turns on login timer to auto log out
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role
        
        failed_logins.pop((ip, username), None)
        
        return redirect(url_for("dashboard"))
    
    return """
        <form method="POST">
            <input name="username" placeholder="Username">
            <input name="password" type=password placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    """
    
@app.route("/dashboard")
@login_required
def dashboard():    
    return f"""
        <h1>Dashboard</h1>
        <p>You are logged in as {session["username"]}</p>
        <a href="/logout">Logout</a>
    """
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin_required
def admin_panel():
    return f"""
        <h1>Admin Panel</h1><p>Welcome, {session["username"]}</p>
    """
    
if __name__ == "__main__":
    # without use_reloader the app was crashing because of spiderIDE
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
