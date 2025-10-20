import os
import re
import asyncio
import logging
from datetime import datetime
from fastapi import HTTPException, UploadFile, status, Request
from sqlalchemy.orm import Session
from db.models import File, Analysis
from api.schemas.dependencies import validate_pcap_header, calculate_file_hash 
from core.rate_limiter import upload_rate_limiter
from core.config import UPLOAD_DIRECTORY
from task_runner import run_analysis_task

UPLOAD_DIR = UPLOAD_DIRECTORY
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB

async def create_file(session: Session, file: UploadFile, user_id: str, request: Request) -> File:
    allowed = await upload_rate_limiter.is_allowed(user_id)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Limite de uploads atingido. Tente novamente mais tarde."
        )

    try:
        new_file, analysis = await asyncio.to_thread(_create_file_sync, session, file, user_id)

        process_pool = request.app.state.process_pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logging.getLogger("sharpshark.files").info(f"Análise {analysis.id} submetida ao Process Pool a partir da API.")

        return new_file
    except HTTPException as e:
        raise e
    except Exception as e:
        logging.getLogger("sharpshark.files").exception("Erro inesperado em _create_file_sync")
        raise HTTPException(status_code=500, detail=f"Erro interno ao processar ficheiro: {e}")

def _create_file_sync(session: Session, file: UploadFile, user_id: str) -> tuple[File, Analysis]:
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    if not file.filename.endswith((".pcapng", ".pcap")):
        raise HTTPException(status_code=400, detail="Apenas ficheiros .pcapng e .pcap são permitidos")

    validate_pcap_header(file)

    try:
        size_bytes = file.file.seek(0, 2)
        file.file.seek(0)
    except Exception:
        raise HTTPException(status_code=400, detail="Não foi possível determinar o tamanho do ficheiro.")

    if size_bytes > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Ficheiro excede o limite máximo de 100 MB")
    
    if size_bytes == 0:
        raise HTTPException(status_code=400, detail="Ficheiro vazio")

    file_hash = calculate_file_hash(file)

    existing = session.query(File).filter(File.file_hash == file_hash).first()
    if existing:
        raise HTTPException(status_code=400, detail="Ficheiro já foi registado anteriormente")

    original_name, ext = os.path.splitext(os.path.basename(file.filename))
    clean_name = re.sub(r"[^\w\-]", "-", original_name)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")[:-3]
    filename = f"{clean_name}_{timestamp}{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as buffer:
        file.file.seek(0)
        buffer.write(file.file.read())

    file_size_mb = os.path.getsize(file_path) / 1024 / 1024
    new_file = File(
        file_name=filename,
        file_path=file_path,
        file_size=file_size_mb,
        file_hash=file_hash,
        user_id=user_id,
    )
    
    session.add(new_file)
    session.flush()

    analysis = Analysis(
        file_id=new_file.id,
        user_id=user_id,
        status="pending",
        total_packets=0,
        total_streams=0,
        duration=0.0
    )
    
    session.add(analysis)
    session.commit()
    session.refresh(new_file)
    session.refresh(analysis)
    
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
    
    try:
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
    except Exception as e:
        logging.getLogger("sharpshark.files").warning(f"[WARN] Erro ao remover ficheiro principal: {e}")

    session.delete(file)
    session.commit()

