# -*- coding: utf-8 -*-
"""
Created on Sat Jan 31 11:47:16 2026

@author: inder
"""

from flask import Flask, session, redirect, url_for
from functools import wraps
# Classes I made
from config import Config
from db import init_db
from auth import auth

app = Flask(__name__)
app.config.from_object(Config)

init_db()

app.register_blueprint(auth)
        
# =====================
# Decorators
# =====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
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

# =====================
# Protected routes
# =====================
@app.route("/")
def home():
    return "Hello, world!"
    
@app.route("/dashboard")
@login_required
def dashboard():    
    return f"""
        <h1>Dashboard</h1>
        <p>You are logged in as {session["username"]}</p>
        <a href="/logout">Logout</a>
    """

@app.route("/admin")
@admin_required
def admin_panel():
    return f"""
        <h1>Admin Panel</h1><p>Welcome, {session["username"]}</p>
    """
    
if __name__ == "__main__":
    # without use_reloader the app was crashing because of spiderIDE
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
