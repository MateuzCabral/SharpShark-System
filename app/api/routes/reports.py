from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session
from services.reports import get_report_data

reports_router = APIRouter(prefix="/reports", tags=["Reports"])

@reports_router.get("/{analysis_id}")
def report_data(analysis_id: str, session: Session = Depends(get_session)):
    return get_report_data(session, analysis_id)
