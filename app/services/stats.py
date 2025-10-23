from sqlalchemy.orm import Session
from db.models import Stat

def get_stats(session: Session, category: str = None):
    """
    Busca todas as estatísticas, opcionalmente filtradas por categoria.
    """
    query = session.query(Stat)
    if category:
        query = query.filter(Stat.category == category)
    return query.all()


def get_stats_by_analysis(session: Session, analysis_id: str):
    """
    Busca todas as estatísticas de uma análise específica.
    """
    return session.query(Stat).filter(Stat.analysis_id == analysis_id).all()