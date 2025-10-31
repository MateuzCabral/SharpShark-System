import logging
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from fastapi import HTTPException, status
from db.models import User
from core.security import argon_context
from api.schemas.userSchema import UserCreate, UserUpdate
from typing import Optional

logger = logging.getLogger("sharpshark.users")

def create_user(session: Session, user_schema: UserCreate) -> User:
    logger.info(f"Tentando criar usuário: {user_schema.name}")
    
    existing_user = find_user_by_name(user_schema.name, session)
    if existing_user:
        logger.warning(f"Tentativa de criar usuário já existente: {user_schema.name}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nome de usuário já cadastrado")

    try:
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
        logger.info(f"Usuário '{new_user.name}' (ID: {new_user.id}) criado com sucesso.")
        return new_user
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro DB ao criar usuário '{user_schema.name}': {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao criar usuário.")
    except Exception as e:
        session.rollback()
        logger.exception(f"Erro inesperado ao criar usuário '{user_schema.name}': {e}")
        raise HTTPException(status_code=500, detail="Erro interno inesperado ao criar usuário.")


def get_users_query(session: Session):
    return session.query(User)

def get_user_by_id(session: Session, user_id: str) -> User:
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        logger.info(f"Tentativa de acesso a usuário não existente: ID {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    return user

def find_user_by_name(name: str, session: Session) -> Optional[User]:
    return session.query(User).filter(User.name == name).first()

def update_user(session: Session, user_id: str, user_update: UserUpdate) -> User:
    logger.info(f"Tentando atualizar usuário ID: {user_id}")
    user = get_user_by_id(session, user_id)

    updated_fields = []

    try:
        if user_update.name and user_update.name != user.name:
            existing_user = find_user_by_name(user_update.name, session)
            if existing_user:
                logger.warning(f"Tentativa de atualizar user {user_id} falhou: nome '{user_update.name}' já existe (user {existing_user.id}).")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nome de usuário já existe")
            user.name = user_update.name
            updated_fields.append("name")

        if user_update.password:
            user.password = argon_context.hash(user_update.password)
            updated_fields.append("password")

        if user_update.is_active is not None and user_update.is_active != user.is_active:
            user.is_active = user_update.is_active
            updated_fields.append(f"is_active={user.is_active}")

        if user_update.is_superuser is not None and user_update.is_superuser != user.is_superuser:
            user.is_superuser = user_update.is_superuser
            updated_fields.append(f"is_superuser={user.is_superuser}")

        if not updated_fields:
             logger.info(f"Nenhuma alteração detectada para usuário ID: {user_id}")
             return user

        session.commit()
        session.refresh(user)
        logger.info(f"Usuário ID {user_id} ('{user.name}') atualizado com sucesso. Campos: {', '.join(updated_fields)}")
        return user
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro DB ao atualizar usuário ID {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao atualizar usuário.")
    except Exception as e:
        session.rollback()
        logger.exception(f"Erro inesperado ao atualizar usuário ID {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno inesperado ao atualizar usuário.")


def delete_user(session: Session, user_id: str):
    logger.info(f"Tentando deletar usuário ID: {user_id}")
    user = get_user_by_id(session, user_id)
    user_name_log = user.name
    try:
        session.delete(user)
        session.commit()
        logger.info(f"Usuário '{user_name_log}' (ID: {user_id}) deletado com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro DB ao deletar usuário '{user_name_log}' (ID: {user_id}): {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao deletar usuário.")
    except Exception as e:
        session.rollback()
        logger.exception(f"Erro inesperado ao deletar usuário '{user_name_log}' (ID: {user_id}): {e}")
        raise HTTPException(status_code=500, detail="Erro interno inesperado ao deletar usuário.")

    return None