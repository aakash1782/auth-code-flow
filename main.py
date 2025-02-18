from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
import sqlite3
import secrets
from datetime import datetime, timedelta

#   Constants
SECRET_KEY = "8c1479528ac6234f60636b5eb223edbb4d2b0b1392c32c128bd407d03f169161"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DB_NAME = "oauth2_server2.db"

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    return sqlite3.connect(DB_NAME)

def create_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,
        client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL
    )""")

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

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

class Token(BaseModel):
    access_token: str
    token_type: str

class ClientRegistration(BaseModel):
    redirect_uri: str

class AuthRequest(BaseModel):
    client_id: str
    redirect_uri: str
    username: str
    password: str

class TokenRequest(BaseModel):
    client_id: str
    client_secret: str
    code: str

app = FastAPI()

@app.post("/register_client")
def register_client(request: ClientRegistration):
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (?, ?, ?)",
                   (client_id, client_secret, request.redirect_uri))
    conn.commit()
    conn.close()

    return {"client_id": client_id, "client_secret": client_secret, "redirect_uri": request.redirect_uri}

@app.post("/register_user")
def register_user(username: str, password: str):
    hashed_password = hash_password(password)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

    return {"message": "User registered successfully"}

@app.get("/authorize")
def authorize(client_id: str, redirect_uri: str, username: str, password: str):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM clients WHERE client_id = ? AND redirect_uri = ?", (client_id, redirect_uri))
    client = cursor.fetchone()
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client or redirect URI")

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user or not verify_password(password, user[2]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    auth_code = secrets.token_urlsafe(16)
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    cursor.execute("INSERT INTO auth_codes (code, client_id, username, expires_at) VALUES (?, ?, ?, ?)",
                   (auth_code, client_id, username, expires_at))
    conn.commit()
    conn.close()

    return {"authorization_code": auth_code, "redirect_uri": redirect_uri}

# Token Exchange Endpoint
@app.post("/token", response_model=Token)
def exchange_token(request: TokenRequest):
    conn = get_db()
    cursor = conn.cursor()

    # Validate Client
    cursor.execute("SELECT * FROM clients WHERE client_id = ? AND client_secret = ?", 
                   (request.client_id, request.client_secret))
    client = cursor.fetchone()
    if not client:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Validate Authorization Code
    cursor.execute("SELECT * FROM auth_codes WHERE code = ? AND client_id = ?", (request.code, request.client_id))
    auth_code = cursor.fetchone()
    if not auth_code:
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    expires_at = datetime.strptime(auth_code[4], "%Y-%m-%d %H:%M:%S.%f")
    if datetime.utcnow() > expires_at:
        raise HTTPException(status_code=400, detail="Authorization code expired")

    username = auth_code[3]

    # Generate Access Token
    access_token = create_access_token(data={"sub": username})

    # Delete Used Authorization Code
    cursor.execute("DELETE FROM auth_codes WHERE code = ?", (request.code,))
    conn.commit()
    conn.close()

    return {"access_token": access_token, "token_type": "bearer"}

# Protected Resource
@app.get("/users/me")
def read_users_me(token: str):
    return {"message": "Secure Data", "token": token}
