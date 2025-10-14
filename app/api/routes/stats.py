from fastapi import APIRouter, Depends, Query
from api.schemas.dependencies import get_session
from sqlalchemy.orm import Session

from services.stats import get_stats, get_stats_by_analysis

stats_router = APIRouter(prefix="/stats", tags=["Stats"])

@stats_router.get("/")
def list_stats(category: str = Query(None), session: Session = Depends(get_session)):
    return get_stats(session, category)

@stats_router.get("/{analysis_id}")
def stats_by_analysis(analysis_id: str, session: Session = Depends(get_session)):
    return get_stats_by_analysis(session, analysis_id)
