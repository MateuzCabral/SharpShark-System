from sqlalchemy.orm import Session
from db.models import Alert
from fastapi import HTTPException

def get_alerts(session: Session, alert_type: str = None, severity: str = None):
    query = session.query(Alert)

    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))
    if severity:
        query = query.filter(Alert.severity == severity)

    alerts = query.all()

    if not alerts:
        raise HTTPException(status_code=404, detail="Nenhum alerta encontrado")

    return alerts