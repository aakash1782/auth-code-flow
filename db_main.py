import sqlite3
from datetime import datetime, timedelta

DB_NAME = "oauth2_server2.db"

def get_db():
    return sqlite3.connect(DB_NAME)

def create_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    
    # Clients Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,
        client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL
    )""")
    
    # Authorization Codes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        client_id TEXT NOT NULL,
        username TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL
    )""")

    conn.commit()
    conn.close()

create_db()
