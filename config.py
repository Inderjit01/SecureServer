# -*- coding: utf-8 -*-
"""
Created on Wed Feb  4 11:56:37 2026

@author: inder
"""

import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    DATABASE_PATH = os.getenv("DATABASE_PATH")

    SESSION_COOKIE_HTTPONLY = True # cookies are only readable through http
    SESSION_COOKIE_SECURE = True # To send cookie: True for https False for https/http
    SESSION_COOKIE_SAMESITE = "Lax" # When the browser uses the cookie: Lax, strict, None
    
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30) # How long until you are auto signed out
    
    