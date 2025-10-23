import logging
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from fastapi import HTTPException, status
from db.models import CustomRule
from api.schemas.customRuleSchema import CustomRuleCreate
from typing import List

logger = logging.getLogger("sharpshark.rules")

def create_rule(db: Session, rule_data: CustomRuleCreate, user_id: str) -> CustomRule:
    logger.info(f"Admin {user_id}: Tentando criar regra '{rule_data.name}' ({rule_data.rule_type})...")
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
        logger.info(f"Admin {user_id}: Regra '{new_rule.name}' (ID: {new_rule.id}) criada com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Admin {user_id}: Erro DB ao criar regra '{rule_data.name}': {e}")
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
        logger.info(f"Tentativa de acesso a regra não existente: ID {rule_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Regra não encontrada")
    return rule

def delete_rule(db: Session, rule_id: str) -> None:
    logger.info(f"Tentando deletar regra ID: {rule_id}...")
    rule = get_rule_by_id(db, rule_id)
    rule_name_log = rule.name
    db.delete(rule)
    try:
        db.commit()
        logger.info(f"Regra '{rule_name_log}' (ID: {rule_id}) deletada com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Erro DB ao deletar regra '{rule_name_log}' (ID: {rule_id}): {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao deletar a regra do banco de dados: {e}"
        )
    return None