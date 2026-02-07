# -*- coding: utf-8 -*-
"""
Created on Wed Feb  4 12:30:18 2026

@author: inder
"""

import sqlite3
from pathlib import Path
# class I made
from config import Config

DB_FILE = Path(Config.DATABASE_PATH)

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    if not DB_FILE.exists():
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
          CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT DEFAULT user
              )             
        """)
        conn.commit()
        conn.close()
        print(f'Database initialized at {DB_FILE}')
    else:
        print(f'Database already exists at {DB_FILE}')
        
def add_user(username, password_hash, role="user"):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)""", 
            (username, password_hash, role)
            )  
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()   

def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, username, password_hash, role FROM users WHERE username = ?""",
            (username,)
        )  
    user = cursor.fetchone()
    conn.commit()
    conn.close()
    return user
      
                       
              
                       
              
                
              
                
        