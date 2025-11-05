from fastapi import APIRouter, Depends, status
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.dependencies import get_session, check_token, require_superuser
import services.custom_rules as rule_service
from api.schemas.customRuleSchema import CustomRuleCreate, CustomRuleRead, CustomRuleUpdate

custom_rules_router = APIRouter(prefix="/rules", tags=["Custom Rules"])

@custom_rules_router.post("/", response_model=CustomRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule_endpoint(
    rule_data: CustomRuleCreate,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user) 
    return rule_service.create_rule(db=session, rule_data=rule_data, user_id=current_user.id)

@custom_rules_router.get("/", response_model=Page[CustomRuleRead])
def list_rules_endpoint(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    query = rule_service.get_rules_query(db=session)
    return paginate(query)

@custom_rules_router.put("/{rule_id}", response_model=CustomRuleRead)
def update_rule_endpoint(
    rule_id: str,
    rule_data: CustomRuleUpdate,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    return rule_service.update_rule(db=session, rule_id=rule_id, rule_data=rule_data)

@custom_rules_router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_endpoint(
    rule_id: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    rule_service.delete_rule(db=session, rule_id=rule_id)
    return None