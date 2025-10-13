from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from db.models import User
from core.security import argon_context
from api.schemas.userSchema import UserCreate, UserUpdate

def create_user(session: Session, user_schema: UserCreate) -> User:
    if session.query(User).filter(User.name == user_schema.name).first():
        raise HTTPException(status_code=400, detail="Usuário já cadastrado")
    hashed = argon_context.hash(user_schema.password)
    new_user = User(
        name=user_schema.name,
        password=hashed,
        is_active=user_schema.is_active,
        is_superuser=user_schema.is_superuser
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user

def get_users_query(session: Session):
    return session.query(User)

def get_user_by_id(session: Session, user_id: str) -> User:
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user

def update_user(session: Session, user_id: str, user_update: UserUpdate) -> User:
    user = get_user_by_id(session, user_id)

    if user_update.name:
        existing_user = session.query(User).filter(User.name == user_update.name, User.id != user.id).first()
        if existing_user:
            raise HTTPException(status_code=409, detail="Nome de usuário já existe")
        user.name = user_update.name

    if user_update.password:
        user.password = argon_context.hash(user_update.password)
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    if user_update.is_superuser is not None:
        user.is_superuser = user_update.is_superuser
    session.commit()
    session.refresh(user)
    return user


def delete_user(session: Session, user_id: str):
    user = get_user_by_id(session, user_id)
    session.delete(user)
    session.commit()
