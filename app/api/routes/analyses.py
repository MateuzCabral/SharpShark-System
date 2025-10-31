from fastapi import APIRouter, Depends, status, HTTPException, Response, Query
from fastapi.responses import FileResponse
from fastapi_pagination import Page, Params
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session, joinedload
from api.schemas.dependencies import get_session, check_token
from api.schemas.analysisSchema import AnalysisRead, AlertRead, IpRecordRead
from db.models import Analysis, Alert, IpRecord
from db.models import File, User, Stream
import os
from core.config import UPLOAD_DIRECTORY 

analyses_router = APIRouter(prefix="/analyses", tags=["analyses"])
STREAMS_BASE_DIR = os.path.abspath(os.path.join(UPLOAD_DIRECTORY, "streams"))
MAX_STREAM_VIEW_SIZE_BYTES = 5 * 1024 * 1024 

@analyses_router.get("/", response_model=Page[AnalysisRead])
def list_analyses(
    params: Params = Depends(),
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    query = session.query(Analysis)
    if not current_user.is_superuser:
        query = query.join(File).filter(File.user_id == current_user.id)
    query = query.options(joinedload(Analysis.file))
    return paginate(query.order_by(Analysis.analyzed_at.desc()), params)

@analyses_router.get("/{analysis_id}", response_model=AnalysisRead)
def get_analysis(
    analysis_id: str, 
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    analysis = session.query(Analysis).options(
        joinedload(Analysis.streams),
        joinedload(Analysis.file)
    ).filter(Analysis.id == analysis_id).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")
    
    if not current_user.is_superuser:
        if analysis.file_id:
            if not analysis.file or analysis.file.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
        else:
            f = session.query(File).filter(File.id == analysis.file_id).first()
            if not f or f.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")

    return analysis

@analyses_router.get("/{analysis_id}/alerts", response_model=Page[AlertRead])
def list_analysis_alerts(
    analysis_id: str, 
    params: Params = Depends(),
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    if not current_user.is_superuser:
        f = session.query(File).filter(File.id == analysis.file_id).first()
        if not f or f.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
    
    query = session.query(Alert).filter(Alert.analysis_id == analysis_id).order_by(Alert.id.desc())
    return paginate(query, params)

@analyses_router.get("/{analysis_id}/ips", response_model=Page[IpRecordRead])
def list_analysis_ips(
    analysis_id: str, 
    params: Params = Depends(),
    role: str = Query(None, description="Filtrar por 'SRC' ou 'DST'"),
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    if not current_user.is_superuser:
        f = session.query(File).filter(File.id == analysis.file_id).first()
        if not f or f.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
    query = session.query(IpRecord).filter(IpRecord.analysis_id == analysis_id)
    
    if role and role.upper() in ["SRC", "DST"]:
        query = query.filter(IpRecord.role == role.upper())

    query = query.order_by(IpRecord.count.desc())
    
    return paginate(query, params)
    
@analyses_router.get("/stream/{stream_id}")
def get_stream_content(
    stream_id: str, 
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    stream = session.query(Stream).filter(Stream.id == stream_id).first()
    if not stream:
        raise HTTPException(status_code=404, detail="Stream não encontrado")

    try:
        owner_id = stream.analysis.file.user_id
    except AttributeError:
        raise HTTPException(status_code=404, detail="Análise ou ficheiro associado ao stream não encontrado")

    if not current_user.is_superuser and owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Sem permissão para acessar este stream")

    file_path_from_db = stream.content_path
    file_path_resolved = os.path.abspath(file_path_from_db)
    
    common_path = os.path.commonpath([file_path_resolved, STREAMS_BASE_DIR])
    
    if not os.path.exists(file_path_resolved) or common_path != STREAMS_BASE_DIR:
        raise HTTPException(status_code=403, detail="Acesso ao ficheiro inválido ou não autorizado.")

    try:
        file_size_bytes = os.path.getsize(file_path_resolved)
        if file_size_bytes > MAX_STREAM_VIEW_SIZE_BYTES:
            raise HTTPException(
                status_code=413, 
                detail=f"Stream muito grande para visualização (limite: {MAX_STREAM_VIEW_SIZE_BYTES / 1024 / 1024} MB)."
            )
    except OSError:
        raise HTTPException(status_code=500, detail="Não foi possível ler o ficheiro do stream.")

    filename = os.path.basename(file_path_resolved).replace(".bin", ".txt")
    
    response = FileResponse(
        path=file_path_resolved, 
        media_type="text/plain", 
        filename=filename,
        content_disposition_type="inline"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    return response