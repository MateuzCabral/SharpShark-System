from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session, require_active_user
from services.alerts import get_alerts
from db.models import User
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from api.schemas.analysisSchema import AlertRead

alert_router = APIRouter(prefix="/alerts", tags=["Alerts"])

@alert_router.get("/", response_model=Page[AlertRead])
def list_alerts(
    alert_type: str = Query(None),
    severity: str = Query(None),
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    query = get_alerts(session, alert_type, severity)
    return paginate(query)