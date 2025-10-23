from fastapi import APIRouter, Depends, status, HTTPException
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User, CustomRule
from api.schemas.dependencies import get_session, check_token, require_superuser
from api.schemas.customRuleSchema import CustomRuleCreate, CustomRuleRead

custom_rules_router = APIRouter(prefix="/rules", tags=["Custom Rules"])

@custom_rules_router.post("/", response_model=CustomRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(
    rule_data: CustomRuleCreate,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    
    new_rule = CustomRule(
        user_id=current_user.id,
        name=rule_data.name,
        rule_type=rule_data.rule_type,
        value=rule_data.value,
        alert_type=rule_data.alert_type,
        severity=rule_data.severity
    )
    session.add(new_rule)
    session.commit()
    session.refresh(new_rule)
    return new_rule

@custom_rules_router.get("/", response_model=Page[CustomRuleRead])
def list_rules(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):

    require_superuser(current_user)

    query = session.query(CustomRule)
    return paginate(query)

@custom_rules_router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):

    require_superuser(current_user)
    
    rule = session.query(CustomRule).filter(CustomRule.id == rule_id).first()
    
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regra não encontrada")
        
    session.delete(rule)
    session.commit()
    return None