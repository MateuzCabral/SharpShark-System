import logging
from datetime import timedelta
from fastapi import HTTPException, status, Request
from sqlalchemy.orm import Session
from db.models import User
from core.security import argon_context, create_access_token, EXPIRE_MINUTES
from core.rate_limiter import login_rate_limiter
import services.users as user_service

logger = logging.getLogger("sharpshark.auth")

async def verify_user_credentials(name: str, password: str, session: Session, request: Request) -> User:
    client_ip = request.client.host if request.client else "IP Desconhecido"
    logger.info(f"Tentativa de login para usuário '{name}' do IP {client_ip}")

    allowed = await login_rate_limiter.is_allowed(client_ip)
    if not allowed:
        logger.warning(f"Rate limit de login atingido para IP {client_ip} (Tentativa user: '{name}')")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Tente novamente em alguns minutos."
        )
    
    user = user_service.find_user_by_name(name, session)

    login_success = False

    if user and user.is_active and argon_context.verify(password, user.password):
        login_success = True

    if not login_success:
        logger.warning(f"Falha na autenticação para usuário '{name}' do IP {client_ip} (User encontrado: {user is not None}, Ativo: {user.is_active if user else 'N/A'})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário ou senha inválidos"
        )
    
    return user

def generate_access_token(user: User) -> dict:
    try:
        access_token = create_access_token(
            str(user.id),
            expires_delta=timedelta(minutes=EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.exception(f"Erro CRÍTICO ao gerar token para user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao gerar token de autenticação."
        )