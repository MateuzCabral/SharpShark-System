import os
import re
import asyncio
import logging
from datetime import datetime
from fastapi import HTTPException, UploadFile, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from db.models import File, Analysis
from api.schemas.dependencies import validate_pcap_header, calculate_file_hash
from core.rate_limiter import upload_rate_limiter
from core.config import UPLOAD_DIRECTORY
from task_runner import run_analysis_task

UPLOAD_DIR = UPLOAD_DIRECTORY
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
logger = logging.getLogger("sharpshark.files")

async def create_file(session: Session, file: UploadFile, user_id: str, request: Request) -> File:
    allowed = await upload_rate_limiter.is_allowed(user_id)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Limite de uploads atingido.")

    try:
        new_file, analysis = await asyncio.to_thread(_create_file_sync, session, file, user_id)
        process_pool = request.app.state.process_pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logger.info(f"Análise {analysis.id} (Arquivo {new_file.id}) submetida ao Process Pool via API.")

        return new_file
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.exception(f"Erro inesperado em create_file (antes ou depois de _create_file_sync): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro interno inesperado ao iniciar processamento do ficheiro.")

def _create_file_sync(session: Session, file: UploadFile, user_id: str) -> tuple[File, Analysis]:
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as e:
        logger.error(f"Falha crítica ao criar diretório de upload {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao acessar armazenamento.")

    if not file.filename or not file.filename.endswith((".pcapng", ".pcap")):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nome de ficheiro inválido ou extensão não permitida (.pcapng, .pcap).")

    try:
        validate_pcap_header(file)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Erro inesperado validando header do ficheiro {file.filename}: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível ler o cabeçalho do ficheiro.")

    try:
        size_bytes = file.file.seek(0, 2)
        file.file.seek(0)
    except (OSError, AttributeError, ValueError) as e:
        logger.warning(f"Erro ao determinar tamanho do ficheiro {file.filename}: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível determinar o tamanho do ficheiro.")

    if size_bytes > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Ficheiro excede o limite máximo de {MAX_UPLOAD_BYTES / 1024 / 1024} MB")
    if size_bytes == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ficheiro vazio não permitido.")

    try:
        file_hash = calculate_file_hash(file)
    except Exception as e:
        logger.error(f"Erro calculando hash do ficheiro {file.filename}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao processar hash do ficheiro.")

    existing = session.query(File.id).filter(File.file_hash == file_hash).first()
    if existing:
        logger.warning(f"Tentativa de upload de ficheiro duplicado (hash {file_hash}): {file.filename}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ficheiro com este conteúdo já foi registado anteriormente.")

    try:
        original_name, ext = os.path.splitext(os.path.basename(file.filename))
        clean_name = re.sub(r"[^\w\-.]", "_", original_name) # Permite pontos
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")[:-3]
        safe_filename = f"{clean_name}_{timestamp}{ext}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)

        with open(file_path, "wb") as buffer:
            file.file.seek(0)
            while chunk := file.file.read(8192):
                 buffer.write(chunk)
            file.file.seek(0)

    except OSError as e:
        logger.error(f"Erro de I/O ao salvar ficheiro {safe_filename} em {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao salvar ficheiro no servidor.")
    except Exception as e:
        logger.exception(f"Erro inesperado ao preparar/salvar ficheiro {file.filename}: {e}")
        if 'file_path' in locals() and os.path.exists(file_path):
             try: os.remove(file_path)
             except OSError: pass
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado ao salvar ficheiro.")

    try:
        file_size_mb = size_bytes / 1024 / 1024
        new_file = File(
            file_name=safe_filename, file_path=file_path, file_size=file_size_mb,
            file_hash=file_hash, user_id=user_id,
        )
        session.add(new_file)
        session.flush()

        analysis = Analysis(
            file_id=new_file.id, user_id=user_id, status="pending"
        )
        session.add(analysis)
        session.commit()
        session.refresh(new_file)
        session.refresh(analysis)
        logger.info(f"Ficheiro {new_file.id} ({new_file.file_name}) e Análise {analysis.id} criados para user {user_id}.")

    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro de DB ao salvar registos para ficheiro {safe_filename} (hash {file_hash}): {e}")
        try:
            if os.path.exists(file_path): os.remove(file_path)
        except OSError as rm_e:
            logger.warning(f"Não foi possível remover ficheiro órfão {file_path} após erro de DB: {rm_e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao registar ficheiro na base de dados.")
    except Exception as e:
        session.rollback()
        logger.exception(f"Erro inesperado ao salvar registos DB para {safe_filename}: {e}")
        try:
             if os.path.exists(file_path): os.remove(file_path)
        except OSError: pass
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado no registo do ficheiro.")

    return new_file, analysis

def get_files_query(session: Session):
    return session.query(File)
def get_file_by_id(session: Session, file_id: str) -> File:
    file = session.query(File).filter(File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return file
def get_file_by_hash(session: Session, file_hash: str) -> File | None:
    hash_file = session.query(File).filter(File.file_hash == file_hash).first()
    if not hash_file:
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return hash_file


def delete_file(session: Session, file_id: str):
    file = get_file_by_id(session, file_id)

    file_path_to_delete = file.file_path

    try:
        session.delete(file)
        session.commit()
        logger.info(f"Registro do ficheiro {file_id} ({os.path.basename(file_path_to_delete)}) deletado do DB.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro de DB ao tentar deletar ficheiro {file_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro ao deletar registro do ficheiro.")

    try:
        if file_path_to_delete and os.path.exists(file_path_to_delete):
            os.remove(file_path_to_delete)
            logger.info(f"Ficheiro físico {file_path_to_delete} removido.")
        elif file_path_to_delete:
             logger.warning(f"Registro DB do ficheiro {file_id} deletado, mas arquivo físico não encontrado em {file_path_to_delete}.")

    except OSError as e:
        logger.warning(f"Erro de I/O ao tentar remover ficheiro físico {file_path_to_delete} após deletar registro DB: {e}")
    except Exception as e:
        logger.warning(f"Erro inesperado ao tentar remover ficheiro físico {file_path_to_delete}: {e}")