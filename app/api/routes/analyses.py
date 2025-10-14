from fastapi import APIRouter, Depends, status, HTTPException
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session, require_active_user, check_token
from api.schemas.analysisSchema import AnalysisRead, AlertRead
from db.models import Analysis, Alert
import services.analysis as analysis_service
import services.files as file_service
from db.models import File, User

analyses_router = APIRouter(prefix="/analyses", tags=["analyses"])

@analyses_router.get("/", response_model=Page[AnalysisRead])
def list_analyses(current_user: User = Depends(check_token), session: Session = Depends(get_session)):
    query = session.query(Analysis)
    if not current_user.is_superuser:
        query = query.join(File).filter(File.user_id == current_user.id)
    return paginate(query)

@analyses_router.get("/{analysis_id}", response_model=AnalysisRead)
def get_analysis(analysis_id: str, current_user: User = Depends(check_token), session: Session = Depends(get_session)):
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if not current_user.is_superuser:
        if analysis.file_id:
            f = session.query(File).filter(File.id == analysis.file_id).first()
            if not f or f.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
    _ = analysis.streams
    _ = analysis.alerts
    _ = analysis.stats
    _ = analysis.ips
    return analysis

@analyses_router.post("/", response_model=AnalysisRead, status_code=status.HTTP_201_CREATED)
def create_analysis(payload: dict, current_user: User = Depends(check_token), session: Session = Depends(get_session)):
    file_id = payload.get("file_id")
    if not file_id:
        raise HTTPException(status_code=400, detail="file_id is required")
    file_obj = session.query(File).filter(File.id == file_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")
    if file_obj.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Sem permissão para analisar este arquivo")

    analysis = analysis_service.analyze_file(session, file_obj)
    return analysis

@analyses_router.get("/{analysis_id}/alerts", response_model=Page[AlertRead])
def list_analysis_alerts(analysis_id: str, current_user: User = Depends(check_token), session: Session = Depends(get_session)):
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if not current_user.is_superuser:
        f = session.query(File).filter(File.id == analysis.file_id).first()
        if not f or f.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
    query = session.query(Alert).filter(Alert.analysis_id == analysis_id)
    return paginate(query)
