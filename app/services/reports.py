from sqlalchemy.orm import Session
from db.models import Analysis, Alert, Stat, Stream, IpRecord
from fastapi import HTTPException

def get_report_data(session: Session, analysis_id: str):
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    alerts = session.query(Alert).filter(Alert.analysis_id == analysis_id).all()
    stats = session.query(Stat).filter(Stat.analysis_id == analysis_id).all()
    streams = session.query(Stream).filter(Stream.analysis_id == analysis_id).all()
    ips = session.query(IpRecord).filter(IpRecord.analysis_id == analysis_id).all()

    return {
        "analysis": analysis,
        "alerts": alerts,
        "stats": stats,
        "streams": streams,
        "ips": ips,
    }
