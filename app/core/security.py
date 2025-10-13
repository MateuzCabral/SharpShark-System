from passlib.context import CryptContext
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
import os
from datetime import datetime, timedelta, timezone
from jose import jwt

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
EXPIRE_MINUTES = int(os.getenv("EXPIRE_MINUTES"))

argon_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_schema = OAuth2PasswordBearer(tokenUrl="/auth/login-form")

def create_access_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=EXPIRE_MINUTES)
    to_encode = {"exp": now + expires_delta, "iat": now, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
