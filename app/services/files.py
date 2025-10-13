import os
from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from db.models import File
import hashlib

UPLOAD_DIR = "./uploads"

def calculate_file_hash(file: UploadFile) -> str:
    sha256 = hashlib.sha256()
    file.file.seek(0)
    while chunk := file.file.read(8192):
        sha256.update(chunk)
    file.file.seek(0)
    return sha256.hexdigest()

def validate_pcap_header(file: UploadFile):
    header = file.file.read(4)
    file.file.seek(0)

    # .pcap (2 possíveis headers)
    if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:
        return "pcap"

    # .pcapng
    if header == b'\x0a\x0d\x0d\x0a':
        return "pcapng"

    raise HTTPException(
        status_code=400,
        detail="Arquivo inválido: o conteúdo não corresponde a um arquivo .pcap ou .pcapng"
    )


def create_file(session: Session, file: UploadFile, user_id: str) -> File:
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    if not file.filename.endswith((".pcapng", ".pcap")):
        raise HTTPException(status_code=400, detail="Apenas arquivos .pcapng e .pcap são permitidos")

    validate_pcap_header(file)

    file_hash = calculate_file_hash(file)

    existing = session.query(File).filter(File.file_hash == file_hash).first()
    if existing:
        raise HTTPException(status_code=400, detail="Arquivo já foi registrado anteriormente")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    if os.path.exists(file_path):
        raise HTTPException(status_code=400, detail="Um arquivo com o mesmo nome já existe")

    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())

    file_size = os.path.getsize(file_path) / 1024 / 1024  # MB
    new_file = File(
        file_name=file.filename,
        file_path=file_path,
        file_size=file_size,
        file_hash=file_hash,
        user_id=user_id,
    )

    session.add(new_file)
    session.commit()
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
        os.remove(file.file_path)
    except FileNotFoundError:
        pass

    session.delete(file)
    session.commit()