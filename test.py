from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List
import sqlite3
import os
from db import create_db

app = FastAPI()

create_db()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "8c1479528ac6234f60636b5eb223edbb4d2b0b1392c32c128bd407d03f169161"
ALGORITHM = "HS256"
DB_PATH = "oauth2_server.db"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Role(BaseModel):
    role: str

class SignUpForm(BaseModel):
    username: str
    password: str
    role: str


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn

def get_user_by_username(username: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"id": user[0], "username": user[1], "password": user[2], "role": user[3]}
    return None

def create_user(username: str, password: str, role: str):
    conn = get_db()
    cursor = conn.cursor()
    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
    conn.commit()
    conn.close()

def create_client(client_id: str, client_secret: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO clients (client_id, client_secret) VALUES (?, ?)", (client_id, client_secret))
    conn.commit()
    conn.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

def get_current_role(user: dict = Depends(get_current_user)):
    return user["role"]

# Role-based access
def role_required(allowed_roles: List[str]):
    def role_checker(current_role: str = Depends(get_current_role)):
        if current_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource",
            )
        return current_role
    return role_checker


# Routes
@app.post("/sign_up", status_code=status.HTTP_201_CREATED)
async def sign_up(sign_up_form: SignUpForm):
    user = get_user_by_username(sign_up_form.username)
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    create_user(sign_up_form.username, sign_up_form.password, sign_up_form.role)
    return {"message": "User created successfully"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)
    if user is None or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users/me/role", response_model=Role)
async def read_users_role(current_role: str = Depends(get_current_role)):
    return {"role": current_role}

# Example routes with role-based access

@app.get("/admin_dashboard", response_model=str)
async def admin_dashboard(current_role: str = Depends(role_required(["admin"]))):
    return "Welcome to the Admin Dashboard!"

@app.get("/manager_dashboard", response_model=str)
async def manager_dashboard(current_role: str = Depends(role_required(["admin", "manager"]))):
    return "Welcome to the Manager Dashboard!"

@app.get("/employee_dashboard", response_model=str)
async def employee_dashboard(current_role: str = Depends(role_required(["admin", "manager", "employee"]))):
    return "Welcome to the Employee Dashboard!"

@app.get("/admin_only", response_model=str)
async def admin_only(current_role: str = Depends(role_required(["admin"]))):
    return "This is an admin-only resource."

@app.get("/manager_and_above", response_model=str)
async def manager_and_above(current_role: str = Depends(role_required(["admin", "manager"]))):
    return "This resource is available for managers and above."

@app.get("/employee_and_above", response_model=str)
async def employee_and_above(current_role: str = Depends(role_required(["admin", "manager", "employee"]))):
    return "This resource is available for employees and above."


# Restricted access to specific role resources
@app.get("/restricted_admin", response_model=str)
async def restricted_admin(current_role: str = Depends(role_required(["admin"]))):
    return "Only Admin can access this."

@app.get("/restricted_manager", response_model=str)
async def restricted_manager(current_role: str = Depends(role_required(["manager"]))):
    return "Only Manager can access this."

@app.get("/restricted_employee", response_model=str)
async def restricted_employee(current_role: str = Depends(role_required(["employee"]))):
    return "Only Employee can access this."

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
