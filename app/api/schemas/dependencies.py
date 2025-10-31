from fastapi import Depends, HTTPException, status, UploadFile
from sqlalchemy.orm import sessionmaker, Session
from db.models import db, User
from jose import jwt, JWTError
from core.security import SECRET_KEY, ALGORITHM, oauth2_schema
import hashlib

SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def check_token(
    token: str = Depends(oauth2_schema),
    session: Session = Depends(get_session)
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        user_id = str(sub)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or expired")
    
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

def require_superuser(user: User):
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas superusers podem acessar este recurso"
        )

def require_active_user(current_user: User = Depends(check_token)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuário Inativo")
    return current_user


def calculate_file_hash(file: UploadFile) -> str:
    sha256 = hashlib.sha256()
    file.file.seek(0)
    while chunk := file.file.read(8192):
        sha256.update(chunk)
    file.file.seek(0)
    return sha256.hexdigest()

def validate_pcap_header(file: UploadFile):
    header = file.file.read(4)
    file.file.seek(0)

    if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:
        return "pcap"

    if header == b'\x0a\x0d\x0d\x0a':
        return "pcapng"

    raise HTTPException(
        status_code=400,
        detail="Arquivo inválido: o conteúdo não corresponde a um arquivo .pcap ou .pcapng"
    )