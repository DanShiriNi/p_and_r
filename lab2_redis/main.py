from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
import bcrypt
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware
import redis
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import json
r = redis.Redis(
    host='77.91.86.135',
    port=6379,
    password='eYVX7EwVmmxKPCDmwMtyKVge8oLd2t81',
    decode_responses=True
)
REDIS_KEY = "users_shishelov"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    password: str
class UserResponse(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    disabled: bool | None = None
class Token(BaseModel):
    access_token: str
    token_type: str
# Вспомогательные функции
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
def get_user(username: str):
    users = r.lrange(REDIS_KEY, 0, -1)
    for user_json in users:
        user_data = json.loads(user_json)
        if user_data["username"] == username:
            return user_data
    return None
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user
@app.post("/register/", response_model=UserResponse)
def register_user(user: UserCreate):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = hash_password(user.password)
    user_data = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name or "",
        "hashed_password": hashed_password,
        "disabled": False
    }
    r.rpush(REDIS_KEY, json.dumps(user_data))
    return "User registered!"
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user['username']},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}
@app.get("/users/", response_model=list[UserResponse])
def get_users():
    users = []
    for user_json in r.lrange(REDIS_KEY, 0, -1):
        user_data = json.loads(user_json)
        users.append(UserResponse(
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"],
            disabled=user_data["disabled"]
        ))
    return users