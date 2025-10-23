from fastapi import APIRouter, Depends, status, HTTPException
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.userSchema import UserCreate, UserRead, UserUpdate
from api.schemas.dependencies import get_session, check_token, require_superuser
import services.users as user_service

# Define o roteador para a seção de Gerenciamento de Usuários
users_router = APIRouter(prefix="/users", tags=["users"])

@users_router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    user_schema: UserCreate, # Dados do novo usuário (nome, senha)
    session: Session = Depends(get_session)
):
    """
    Endpoint público para registrar um novo usuário.
    A senha é hasheada pelo 'user_service'.
    """
    return user_service.create_user(session, user_schema)

@users_router.get("/", response_model=Page[UserRead])
def get_all_users(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Lista todos os usuários do sistema, com paginação. Apenas superusuários.
    """
    require_superuser(current_user)
    query = user_service.get_users_query(session)
    return paginate(query)

@users_router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Obtém informações de um usuário específico pelo ID. Apenas superusuários.
    """
    require_superuser(current_user)
    return user_service.get_user_by_id(session, user_id)

@users_router.put("/{user_id}", response_model=UserRead)
def update_user(
    user_id: str,
    user_update: UserUpdate, # Dados a serem atualizados
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Atualiza informações de um usuário (nome, senha, status). Apenas superusuários.
    """
    require_superuser(current_user)
    return user_service.update_user(session, user_id, user_update)

@users_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Deleta um usuário. Apenas superusuários.
    """
    require_superuser(current_user)
    user_service.delete_user(session, user_id)
    return None

@users_router.get("/name/{user_name}", response_model=UserRead)
def get_user_by_name(
    user_name: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Busca um usuário pelo nome exato. Apenas superusuários.
    """
    require_superuser(current_user)
    user = user_service.find_user_by_name(user_name, session)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com nome '{user_name}' não encontrado"
        )
    return user