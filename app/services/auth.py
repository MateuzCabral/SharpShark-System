from datetime import timedelta
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from db.models import User
from core.security import argon_context, create_access_token, EXPIRE_MINUTES

def find_user_by_name(name: str, session: Session) -> User | None:
    return session.query(User).filter(User.name == name).first()

def verify_user_credentials(name: str, password: str, session: Session) -> User:
    user = find_user_by_name(name, session)

    if not user or not user.is_active or not argon_context.verify(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário ou senha inválidos"
        )
    return user

def generate_access_token(user: User) -> dict:
    access_token = create_access_token(
        str(user.id),
        expires_delta=timedelta(minutes=EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}
