from sqlalchemy.orm import Session
from db.models import Alert
from fastapi import HTTPException
from sqlalchemy.orm.query import Query

def get_alerts(session: Session, alert_type: str = None, severity: str = None) -> Query:
    """
    Busca alertas no banco de dados, com filtros opcionais.
    
    RETORNA: O objeto Query do SQLAlchemy, não os resultados.
    """
    # Inicia a query base para a tabela Alert
    query = session.query(Alert)

    # Aplica filtro de 'alert_type' se fornecido (usando 'ilike' para case-insensitive partial match)
    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))
    # Aplica filtro de 'severity' se fornecido (match exato)
    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(Alert.id.desc()) # Adiciona uma ordem padrão