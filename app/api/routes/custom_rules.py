from fastapi import APIRouter, Depends, status, HTTPException
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User
# Importa dependências de sessão, token e o verificador de superusuário
from api.schemas.dependencies import get_session, check_token, require_superuser
import services.custom_rules as rule_service
from api.schemas.customRuleSchema import CustomRuleCreate, CustomRuleRead

# Define o roteador para a seção de Regras Customizadas
custom_rules_router = APIRouter(prefix="/rules", tags=["Custom Rules"])

@custom_rules_router.post("/", response_model=CustomRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule_endpoint(
    rule_data: CustomRuleCreate, # Dados da regra a ser criada
    current_user: User = Depends(check_token), # Pega o usuário logado
    session: Session = Depends(get_session)
):
    """
    Cria uma nova regra customizada. Apenas superusuários.
    """
    # Verifica se o usuário logado é superusuário, caso contrário, lança 403 Forbidden
    require_superuser(current_user) 
    # Chama o serviço para criar a regra no banco
    return rule_service.create_rule(db=session, rule_data=rule_data, user_id=current_user.id)

@custom_rules_router.get("/", response_model=Page[CustomRuleRead])
def list_rules_endpoint(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Lista todas as regras customizadas, com paginação. Apenas superusuários.
    """
    require_superuser(current_user)
    query = rule_service.get_rules_query(db=session)
    return paginate(query)

@custom_rules_router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_endpoint(
    rule_id: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Deleta uma regra customizada pelo ID. Apenas superusuários.
    """
    require_superuser(current_user)
    rule_service.delete_rule(db=session, rule_id=rule_id)
    # Retorna None com status 204 (No Content) em caso de sucesso
    return None