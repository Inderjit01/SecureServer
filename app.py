# -*- coding: utf-8 -*-
"""
Created on Sat Jan 31 11:47:16 2026

@author: inder
"""

from flask import Flask, request, session, redirect, url_for
import bcrypt
# Classes I made
from config import Config
from db import init_db, add_user, get_user_by_username

app = Flask(__name__)
app.config.from_object(Config)

init_db()

@app.route("/")
def home():
    return "Hello, world!"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
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
    
    return """
        <form method="POST">
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

        # makes sure the username exists in the database        
        user_info = get_user_by_username(username)
        if not user_info:
            return "Username or password incorrect", 401
        
        user_id, un, password_hash = user_info
        
        # checks the password the user is trying to login with to the password stored in the db
        if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
            return "Username or password incorrect", 401
        
        # saves the user_id to the flask session method
        session["user_id"] = user_id
        
        return redirect(url_for("dashboard"))
    
    return """
        <form method="POST">
            <input name="username" placeholder="Username">
            <input name="password" type=password placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    """
    
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    return """
        <h1>Dashboard</h1>
        <p>You are logged in as user ID {session["user_id"]}</p>
        <a href="/logout">Logout</a>
    """
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
    
if __name__ == "__main__":
    # without use_reloader the app was crashing because of spiderIDE
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
