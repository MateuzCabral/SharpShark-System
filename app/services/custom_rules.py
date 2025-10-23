from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from db.models import CustomRule
from api.schemas.customRuleSchema import CustomRuleCreate
from typing import List

def create_rule(db: Session, rule_data: CustomRuleCreate, user_id: str) -> CustomRule:
    new_rule = CustomRule(
        user_id=user_id,
        name=rule_data.name,
        rule_type=rule_data.rule_type,
        value=rule_data.value,
        alert_type=rule_data.alert_type,
        severity=rule_data.severity
    )
    db.add(new_rule)
    try:
        db.commit()
        db.refresh(new_rule)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao salvar a regra no banco de dados: {e}"
        )
    return new_rule

def get_rules_query(db: Session):
    return db.query(CustomRule)

def get_rule_by_id(db: Session, rule_id: str) -> CustomRule:
    rule = db.query(CustomRule).filter(CustomRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regra não encontrada")
    return rule

def delete_rule(db: Session, rule_id: str) -> None:
    rule = get_rule_by_id(db, rule_id)
    db.delete(rule)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao deletar a regra do banco de dados: {e}"
        )
    return None