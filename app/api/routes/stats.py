from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
import traceback
from api.schemas.dependencies import get_session, require_active_user
import services.stats as stats_service
from db.models import Analysis, User

stats_router = APIRouter(prefix="/stats", tags=["Stats"])

@stats_router.get("/")
def list_stats_endpoint(
    category: str = Query(None, description="Filtrar estatísticas por uma categoria específica (ex: protocol, port)"),
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    try:
        stats_data = stats_service.get_aggregated_stats(session, category)
        if category and not stats_data:
             raise HTTPException(status_code=404, detail=f"Nenhuma estatística encontrada para a categoria '{category}'")
        if not category and not stats_data:
             return {}
        return stats_data
    except Exception as e:
        print(f"Erro inesperado em GET /stats: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Erro interno ao buscar estatísticas.")


@stats_router.get("/analysis/{analysis_id}")
def stats_by_analysis_endpoint(analysis_id: str, current_user: User = Depends(require_active_user), session: Session = Depends(get_session)):
    analysis_exists = session.query(Analysis.id).filter(Analysis.id == analysis_id).first()
    if not analysis_exists:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    try:
        stats_list = stats_service.get_stats_for_analysis(session, analysis_id)
        return stats_list
    except Exception as e:
        print(f"Erro inesperado em GET /stats/analysis/{analysis_id}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Erro interno ao buscar estatísticas da análise.")


@stats_router.get("/dashboard/summary")
def get_dashboard_summary_endpoint(session: Session = Depends(get_session), current_user: User = Depends(require_active_user)):
    try:
        summary_data = stats_service.calculate_dashboard_summary(session)
        return summary_data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Erro interno ao calcular o sumário do dashboard.")