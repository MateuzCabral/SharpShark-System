from sqlalchemy.orm import Session
from db.models import Alert
from fastapi import HTTPException

def get_alerts(session: Session, alert_type: str = None, severity: str = None):
    """
    Busca alertas no banco de dados, com filtros opcionais.
    """
    # Inicia a query base para a tabela Alert
    query = session.query(Alert)

    # Aplica filtro de 'alert_type' se fornecido (usando 'ilike' para case-insensitive partial match)
    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))
    # Aplica filtro de 'severity' se fornecido (match exato)
    if severity:
        query = query.filter(Alert.severity == severity)

    # Executa a query
    alerts = query.all()

    # Se a query não retornar nada, levanta um erro 404
    if not alerts:
        raise HTTPException(status_code=404, detail="Nenhum alerta encontrado")

    return alerts