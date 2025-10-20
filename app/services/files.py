import os
import re
from datetime import datetime
from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from db.models import File, Analysis
from api.schemas.dependencies import validate_pcap_header, calculate_file_hash 
from core.rate_limiter import upload_rate_limiter
from core.config import UPLOAD_DIRECTORY
import asyncio # Importe asyncio

UPLOAD_DIR = UPLOAD_DIRECTORY
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB

def _create_file_sync(session: Session, file: UploadFile, user_id: str) -> File:

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    if not file.filename.endswith((".pcapng", ".pcap")):
        raise HTTPException(status_code=400, detail="Apenas arquivos .pcapng e .pcap são permitidos")

    validate_pcap_header(file)

    try:
        cur_pos = file.file.tell()
        file.file.seek(0, os.SEEK_END)
        size_bytes = file.file.tell()
        file.file.seek(cur_pos or 0)
    except Exception:
        file.file.seek(0)
        size_bytes = 0
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > MAX_UPLOAD_BYTES:
                break
        file.file.seek(0)

    if size_bytes > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Arquivo excede o limite máximo de 100 MB")

    file_hash = calculate_file_hash(file)

    existing = session.query(File).filter(File.file_hash == file_hash).first()
    if existing:
        raise HTTPException(status_code=400, detail="Arquivo já foi registrado anteriormente")

    original_name, ext = os.path.splitext(os.path.basename(file.filename))
    clean_name = re.sub(r"[^\w\-]", "-", original_name)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")[:-3]
    filename = f"{clean_name}_{timestamp}{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    counter = 1
    while os.path.exists(file_path):
        filename = f"{clean_name}_{timestamp}_{counter}{ext}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        counter += 1

    with open(file_path, "wb") as buffer:
        file.file.seek(0)
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            buffer.write(chunk)

    file_size_mb = os.path.getsize(file_path) / 1024 / 1024
    new_file = File(
        file_name=filename,
        file_path=file_path,
        file_size=file_size_mb,
        file_hash=file_hash,
        user_id=user_id,
    )

    session.add(new_file)
    session.commit()
    session.refresh(new_file)

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
    session.refresh(analysis)

    return new_file

async def create_file(session: Session, file: UploadFile, user_id: str) -> File:
    allowed = await upload_rate_limiter.is_allowed(user_id)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Limite de uploads atingido. Tente novamente mais tarde."
        )

    try:
        new_file = await asyncio.to_thread(_create_file_sync, session, file, user_id)
        return new_file
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno ao processar arquivo: {e}")



def get_files_query(session: Session):
    return session.query(File)


def get_file_by_id(session: Session, file_id: str) -> File:
    file = session.query(File).filter(File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    return file


def get_file_by_hash(session: Session, file_hash: str) -> File | None:
    hash_file = session.query(File).filter(File.file_hash == file_hash).first()
    if not hash_file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    return hash_file


def delete_file(session: Session, file_id: str):
    file = get_file_by_id(session, file_id)
    if not file:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")

    try:
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
    except Exception as e:
        print(f"[WARN] Erro ao remover arquivo principal: {e}")

    try:
        for analysis in file.analysis:
            streams_dir = os.path.join("uploads", "streams")
            if not os.path.exists(streams_dir):
                continue
            for stream_file in os.listdir(streams_dir):
                if stream_file.startswith(str(analysis.id)):
                    try:
                        os.remove(os.path.join(streams_dir, stream_file))
                    except Exception as e:
                        print(f"[WARN] Falha ao remover stream {stream_file}: {e}")
    except Exception as e:
        print(f"[WARN] Erro ao limpar streams: {e}")

    session.delete(file)
    session.commit()
