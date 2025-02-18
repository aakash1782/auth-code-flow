import sqlite3

def create_db():
    conn = sqlite3.connect('oauth2_server.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT
                 )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT UNIQUE,
                    client_secret TEXT
                 )''')

    conn.commit()
    conn.close()

create_db()
