from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session
from services.alerts import get_alerts

alert_router = APIRouter(prefix="/alerts", tags=["Alerts"])

@alert_router.get("/")
def list_alerts(
    alert_type: str = Query(None),
    severity: str = Query(None),
    session: Session = Depends(get_session)
):
    return get_alerts(session, alert_type, severity)
