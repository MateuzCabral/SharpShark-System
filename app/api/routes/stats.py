from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
import traceback # Para log de erros
from api.schemas.dependencies import get_session, require_active_user
import services.stats as stats_service
from db.models import Analysis, User # Para verificar existência em get_stats_by_analysis

# Define o roteador para a seção de Estatísticas
stats_router = APIRouter(prefix="/stats", tags=["Stats"])

@stats_router.get("/")
def list_stats_endpoint(
    category: str = Query(None, description="Filtrar estatísticas por uma categoria específica (ex: protocol, port)"),
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    """
    Lista estatísticas gerais agregadas por categoria e chave.

    - Se nenhuma categoria for fornecida, retorna um dicionário com todas as categorias.
    - Se uma categoria for fornecida, retorna uma lista de estatísticas para essa categoria.
    """
    try:
        stats_data = stats_service.get_aggregated_stats(session, category)
        # Se uma categoria foi pedida mas não encontrada, retorna 404
        if category and not stats_data:
             raise HTTPException(status_code=404, detail=f"Nenhuma estatística encontrada para a categoria '{category}'")
        # Se não há stats no geral, retorna dicionário vazio
        if not category and not stats_data:
             return {}
        return stats_data
    except Exception as e:
        print(f"Erro inesperado em GET /stats: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Erro interno ao buscar estatísticas.")


@stats_router.get("/analysis/{analysis_id}")
def stats_by_analysis_endpoint(analysis_id: str, current_user: User = Depends(require_active_user), session: Session = Depends(get_session)):
    """
    Lista todas as estatísticas brutas (objetos Stat) associadas a uma análise específica.
    """
    # Verifica primeiro se a análise existe para dar um 404 claro
    analysis_exists = session.query(Analysis.id).filter(Analysis.id == analysis_id).first()
    if not analysis_exists:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    try:
        stats_list = stats_service.get_stats_for_analysis(session, analysis_id)
        # Retorna lista vazia se a análise existir mas não tiver stats
        return stats_list
    except Exception as e:
        print(f"Erro inesperado em GET /stats/analysis/{analysis_id}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Erro interno ao buscar estatísticas da análise.")


@stats_router.get("/dashboard/summary")
def get_dashboard_summary_endpoint(session: Session = Depends(get_session), current_user: User = Depends(require_active_user)): # Nome diferente
    """
    Endpoint que retorna as estatísticas agregadas para o dashboard principal.
    """
    try:
        summary_data = stats_service.calculate_dashboard_summary(session)
        return summary_data
    except Exception as e:
        # O erro já foi logado no service, aqui apenas retornamos 500
        # O traceback.print_exc() no service dará mais detalhes no log do servidor
        raise HTTPException(status_code=500, detail="Erro interno ao calcular o sumário do dashboard.")