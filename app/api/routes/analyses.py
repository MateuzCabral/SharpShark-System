from fastapi import APIRouter, Depends, status, HTTPException, Response 
from fastapi.responses import FileResponse
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session, joinedload
from api.schemas.dependencies import get_session, check_token
from api.schemas.analysisSchema import AnalysisRead, AlertRead
from db.models import Analysis, Alert
import services.analysis as analysis_service
from db.models import File, User, Stream
import os
from core.config import UPLOAD_DIRECTORY 

# Define o roteador para a seção de Análises
analyses_router = APIRouter(prefix="/analyses", tags=["analyses"])

# Define o diretório base onde os streams (partes da captura) são salvos
STREAMS_BASE_DIR = os.path.abspath(os.path.join(UPLOAD_DIRECTORY, "streams"))
# Define um limite de segurança para visualização de streams (5MB)
MAX_STREAM_VIEW_SIZE_BYTES = 5 * 1024 * 1024 

@analyses_router.get("/", response_model=Page[AnalysisRead])
def list_analyses(
    # Dependência de autenticação: obtém o usuário atual a partir do token
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    """
    Lista todas as análises com paginação.
    - Superusuários veem todas as análises.
    - Usuários normais veem apenas as análises de seus próprios arquivos.
    """
    query = session.query(Analysis)
    # Filtra a query se o usuário não for superuser
    if not current_user.is_superuser:
        query = query.join(File).filter(File.user_id == current_user.id)
    # Retorna os resultados paginados
    return paginate(query)

@analyses_router.get("/{analysis_id}", response_model=AnalysisRead)
def get_analysis(
    analysis_id: str, 
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    """
    Obtém os detalhes de uma análise específica pelo seu ID.
    """
    
    # Faz a query pela análise, já carregando relacionamentos (eager loading)
    # Isso evita múltiplas queries ao banco (problema N+1)
    analysis = session.query(Analysis).options(
        joinedload(Analysis.streams).joinedload(Stream.alerts), 
        joinedload(Analysis.alerts),
        joinedload(Analysis.stats),
        joinedload(Analysis.ips)
    ).filter(Analysis.id == analysis_id).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")
    
    # Bloco de verificação de permissão
    if not current_user.is_superuser:
        # Verifica se a análise está ligada a um arquivo
        if analysis.file_id:
            # Verifica se o arquivo pertence ao usuário atual
            if not analysis.file or analysis.file.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
        else:
            # Fallback caso 'analysis.file' não esteja carregado
            f = session.query(File).filter(File.id == analysis.file_id).first()
            if not f or f.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")

    return analysis

@analyses_router.get("/{analysis_id}/alerts", response_model=Page[AlertRead])
def list_analysis_alerts(
    analysis_id: str, 
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    """
    Lista todos os alertas associados a uma análise específica, com paginação.
    """
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")

    # Verificação de permissão (semelhante ao endpoint anterior)
    if not current_user.is_superuser:
        f = session.query(File).filter(File.id == analysis.file_id).first()
        if not f or f.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Sem permissão para acessar esta análise")
    
    # Query para buscar os alertas da análise
    query = session.query(Alert).filter(Alert.analysis_id == analysis_id)
    return paginate(query)
    
@analyses_router.get("/stream/{stream_id}")
def get_stream_content(
    stream_id: str, 
    current_user: User = Depends(check_token), 
    session: Session = Depends(get_session)
):
    """
    Retorna o conteúdo de um arquivo de stream (parte da captura) como texto.
    Este endpoint é sensível a segurança (acesso a arquivos).
    """
    
    stream = session.query(Stream).filter(Stream.id == stream_id).first()
    if not stream:
        raise HTTPException(status_code=404, detail="Stream não encontrado")

    # Verifica a permissão do usuário navegando pelos relacionamentos
    # stream -> analysis -> file -> user_id
    try:
        owner_id = stream.analysis.file.user_id
    except AttributeError:
        # Caso algum relacionamento falhe (ex: análise ou arquivo deletado)
        raise HTTPException(status_code=404, detail="Análise ou ficheiro associado ao stream não encontrado")

    if not current_user.is_superuser and owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Sem permissão para acessar este stream")

    # --- Bloco de Segurança de Acesso a Arquivos ---
    file_path_from_db = stream.content_path
    file_path_resolved = os.path.abspath(file_path_from_db)
    
    # Compara o caminho absoluto resolvido com o diretório base permitido
    common_path = os.path.commonpath([file_path_resolved, STREAMS_BASE_DIR])
    
    # Prevenção contra "Path Traversal" (ex: ../../etc/passwd)
    if not os.path.exists(file_path_resolved) or common_path != STREAMS_BASE_DIR:
        raise HTTPException(status_code=403, detail="Acesso ao ficheiro inválido ou não autorizado.")
    # --- Fim do Bloco de Segurança ---

    try:
        # Verifica o tamanho do arquivo antes de lê-lo
        file_size_bytes = os.path.getsize(file_path_resolved)
        if file_size_bytes > MAX_STREAM_VIEW_SIZE_BYTES:
            # Retorna 413 "Payload Too Large" se o arquivo for muito grande
            raise HTTPException(
                status_code=413, 
                detail=f"Stream muito grande para visualização (limite: {MAX_STREAM_VIEW_SIZE_BYTES / 1024 / 1024} MB)."
            )
    except OSError:
        raise HTTPException(status_code=500, detail="Não foi possível ler o ficheiro do stream.")

    # Renomeia o arquivo para .txt para facilitar a visualização no navegador
    filename = os.path.basename(file_path_resolved).replace(".bin", ".txt")
    
    # Retorna o arquivo
    response = FileResponse(
        path=file_path_resolved, 
        media_type="text/plain", # Força o navegador a tratar como texto
        filename=filename,
        content_disposition_type="inline" # Tenta exibir no navegador em vez de baixar
    )
    # Header de segurança para evitar que o navegador tente "adivinhar" o tipo de conteúdo
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    return response