from passlib.context import CryptContext
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
import os
from datetime import datetime, timedelta, timezone
from jose import jwt

load_dotenv()

# --- Configurações de Segurança do JWT ---
SECRET_KEY = os.getenv("SECRET_KEY") # Chave secreta para assinar os tokens
ALGORITHM = os.getenv("ALGORITHM", "HS256") # Algoritmo de assinatura
EXPIRE_MINUTES = int(os.getenv("EXPIRE_MINUTES", 1440)) # 1440 min = 24 horas

# --- Configuração do Hashing de Senhas ---
# Define o 'argon2' como o algoritmo padrão e preferido para hashing
argon_context = CryptContext(schemes=["argon2"], deprecated="auto")

# --- Configuração do OAuth2 (para integração com Swagger) ---
# Informa ao FastAPI e ao Swagger qual endpoint de login usar (o de /login-form)
oauth2_schema = OAuth2PasswordBearer(tokenUrl="/auth/login-form")

def create_access_token(subject: str | int, expires_delta: timedelta | None = None) -> str:
    """
    Cria um novo token de acesso (JWT).
    'subject' (sub) é o ID do usuário.
    """
    now = datetime.now(timezone.utc) # Usa UTC para datas (boa prática)
    if expires_delta is None:
        expires_delta = timedelta(minutes=EXPIRE_MINUTES)
    
    # 'Payload' (carga útil) do token
    to_encode = {
        "exp": now + expires_delta, # Timestamp de expiração
        "iat": now, # Timestamp de emissão (issued at)
        "sub": str(subject) # O 'assunto' do token (ID do usuário)
    }
    # Codifica e assina o token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt