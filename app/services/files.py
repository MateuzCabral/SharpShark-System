import os
from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from db.models import File
from api.schemas.dependencies import validate_pcap_header, calculate_file_hash 
import services.analysis as analysis_service

UPLOAD_DIR = "./uploads"


def create_file(session: Session, file: UploadFile, user_id: str) -> File:
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    if not file.filename.endswith((".pcapng", ".pcap")):
        raise HTTPException(status_code=400, detail="Apenas arquivos .pcapng e .pcap são permitidos")

    validate_pcap_header(file)

    file_hash = calculate_file_hash(file)

    existing = session.query(File).filter(File.file_hash == file_hash).first()
    if existing:
        raise HTTPException(status_code=400, detail="Arquivo já foi registrado anteriormente")

    filename = os.path.basename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(os.path.join(UPLOAD_DIR, f"{base}_{counter}{ext}")):
            counter += 1
        filename = f"{base}_{counter}{ext}"
        file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())

    file_size = os.path.getsize(file_path) / 1024 / 1024  # MB
    new_file = File(
        file_name=filename,
        file_path=file_path,
        file_size=file_size,
        file_hash=file_hash,
        user_id=user_id,
    )

    session.add(new_file)
    session.commit()
    session.refresh(new_file)

    analysis_service.analyze_file(session, new_file)

    session.refresh(new_file)
    return new_file


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
            for stream_file in os.listdir(streams_dir):
                if stream_file.startswith(analysis.id):
                    try:
                        os.remove(os.path.join(streams_dir, stream_file))
                    except Exception as e:
                        print(f"[WARN] Falha ao remover stream {stream_file}: {e}")
    except Exception as e:
        print(f"[WARN] Erro ao limpar streams: {e}")

    session.delete(file)
    session.commit()