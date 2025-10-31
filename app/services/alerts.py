from sqlalchemy.orm import Session
from db.models import Alert
from sqlalchemy.orm.query import Query

def get_alerts(session: Session, alert_type: str = None, severity: str = None) -> Query:
    query = session.query(Alert)

    if alert_type:
        query = query.filter(Alert.alert_type.ilike(f"%{alert_type}%"))
    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(Alert.id.desc())