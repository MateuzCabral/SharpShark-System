from fastapi import APIRouter, Depends, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session
from api.schemas.userSchema import LoginSchema
import services.auth as auth_service

# Define o roteador para a seção de Autenticação
auth_router = APIRouter(prefix="/auth", tags=["auth"])

@auth_router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    login: LoginSchema, # Espera um JSON com 'name' e 'password'
    request: Request, # Injeta o objeto Request (usado pelo rate limiter)
    session: Session = Depends(get_session)
):
    """
    Endpoint de login padrão que aceita JSON.
    """
    # Verifica as credenciais (e o rate limit)
    user = await auth_service.verify_user_credentials(login.name, login.password, session, request)
    # Gera e retorna o token de acesso
    return auth_service.generate_access_token(user)

@auth_router.post("/login-form", status_code=status.HTTP_200_OK)
async def login_form(
    # Dependência especial que lê dados de um formulário (username, password)
    form: OAuth2PasswordRequestForm = Depends(), 
    request: Request = None, 
    session: Session = Depends(get_session)
):
    """
    Endpoint de login que aceita 'form data'.
    Usado para compatibilidade com o Swagger UI (botão "Authorize").
    """
    user = await auth_service.verify_user_credentials(form.username, form.password, session, request)
    return auth_service.generate_access_token(user)