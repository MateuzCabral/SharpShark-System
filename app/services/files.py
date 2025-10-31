import os
import re
import asyncio
import logging
from datetime import datetime
from typing import Tuple
from fastapi import HTTPException, UploadFile, status, Request
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import exc as sqlalchemy_exc
from db.models import File, Analysis, User, Stream
from api.schemas.dependencies import validate_pcap_header, calculate_file_hash
from core.rate_limiter import upload_rate_limiter
from core.config import UPLOAD_DIRECTORY
from task_runner import run_analysis_task

UPLOAD_DIR = UPLOAD_DIRECTORY
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
logger = logging.getLogger("sharpshark.files")

async def create_file(session: Session, file: UploadFile, user_id: str, request: Request) -> File:
    client_ip = request.client.host if request.client else "IP Desconhecido"
    logger.info(f"Recebida tentativa de upload de user {user_id} (IP: {client_ip})")

    if not await upload_rate_limiter.is_allowed(user_id):
        logger.warning(f"User {user_id} (IP: {client_ip}) atingiu limite de upload.")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Limite de uploads atingido. Tente novamente mais tarde."
        )
    try:
        new_file, analysis = await asyncio.to_thread(_create_file_sync, session, file, user_id)

        process_pool = request.app.state.process_pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logger.info(f"Análise {analysis.id} (Arquivo {new_file.id}) submetida ao Process Pool via API (User: {user_id}).")

        return new_file
    
    except HTTPException as e:
        if 400 <= e.status_code < 500:
            logger.info(f"Falha no upload para user {user_id} (IP: {client_ip}): {e.status_code} - {e.detail}")
        else:
            logger.error(f"Erro HTTP {e.status_code} inesperado durante upload (User: {user_id}, IP: {client_ip}): {e.detail}")
        raise e
    except Exception as e:
        logger.exception(f"Erro GERAL inesperado em create_file (User: {user_id}, IP: {client_ip}): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro interno inesperado ao iniciar processamento do ficheiro.")

def _create_file_sync(session: Session, file: UploadFile, user_id: str) -> Tuple[File, Analysis]:
    filename_log = file.filename or "NomeDesconhecido"
    logger.info(f"User {user_id}: Iniciando _create_file_sync para '{filename_log}'")

    try: os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as e:
        logger.error(f"User {user_id}: Falha crítica ao acessar/criar diretório de upload {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao acessar armazenamento.")

    try: validate_pcap_header(file)
    except HTTPException as e:
        logger.info(f"User {user_id}: Upload rejeitado - Header inválido '{filename_log}' - {e.detail}")
        raise e
    except Exception as e:
        logger.warning(f"User {user_id}: Erro inesperado validando header '{filename_log}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível ler o cabeçalho do ficheiro.")
    try:
        size_bytes = file.file.seek(0, 2)
        file.file.seek(0)
    except (OSError, AttributeError, ValueError) as e:
        logger.warning(f"User {user_id}: Erro ao determinar tamanho '{filename_log}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível determinar o tamanho do ficheiro.")
    
    if size_bytes > MAX_UPLOAD_BYTES:
        logger.info(f"User {user_id}: Upload rejeitado - Ficheiro muito grande '{filename_log}' ({size_bytes} bytes)")
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Ficheiro excede o limite máximo de {MAX_UPLOAD_BYTES / 1024 / 1024} MB")
    if size_bytes == 0:
        logger.info(f"User {user_id}: Upload rejeitado - Ficheiro vazio '{filename_log}'")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ficheiro vazio não permitido.")

    try: file_hash = calculate_file_hash(file)
    except Exception as e:
        logger.error(f"User {user_id}: Erro calculando hash '{filename_log}': {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao processar hash do ficheiro.")
    
    existing = session.query(File.id).filter(File.file_hash == file_hash).first()
    if existing:
        logger.info(f"User {user_id}: Upload rejeitado - Hash duplicado '{file_hash}' ('{filename_log}')")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ficheiro com este conteúdo já foi registado anteriormente.")

    file_path = "N/A"
    try:
        original_name, ext = os.path.splitext(os.path.basename(file.filename))
        clean_name = re.sub(r"[^\w\-.]", "_", original_name)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")[:-3]
        safe_filename = f"{clean_name}_{timestamp}{ext}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)

        with open(file_path, "wb") as buffer:
            file.file.seek(0)
            while chunk := file.file.read(8192): buffer.write(chunk)
            file.file.seek(0)
        logger.info(f"User {user_id}: Arquivo físico salvo: {file_path}")
    except OSError as e:
        logger.error(f"User {user_id}: Erro OSError ao salvar '{safe_filename}' em {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao salvar ficheiro no servidor.")
    except Exception as e:
        logger.exception(f"User {user_id}: Erro inesperado ao salvar '{filename_log}': {e}")
        if os.path.exists(file_path):
            try: os.remove(file_path); logger.info(f"User {user_id}: Arquivo parcial removido: {file_path}")
            except OSError: logger.warning(f"User {user_id}: Falha ao remover arquivo parcial {file_path}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado ao salvar ficheiro.")

    try:
        file_size_mb = size_bytes / 1024 / 1024
        
        new_file = File(
            file_name=safe_filename, file_path=file_path, file_size=file_size_mb,
            file_hash=file_hash, user_id=user_id,
        )
        session.add(new_file)
        session.flush()
        
        analysis = Analysis(file_id=new_file.id, user_id=user_id, status="pending")
        session.add(analysis)
        
        session.commit()
        session.refresh(new_file); session.refresh(analysis)
        logger.info(f"User {user_id}: Ficheiro {new_file.id} ({safe_filename}) e Análise {analysis.id} criados no DB.")
    
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"User {user_id}: Erro DB ao salvar registos ('{safe_filename}', Hash: {file_hash}): {e}")
        try:
            if os.path.exists(file_path): os.remove(file_path); logger.info(f"User {user_id}: Arquivo físico órfão removido: {file_path}")
        except OSError as rm_e: logger.warning(f"User {user_id}: Falha remover {file_path} órfão: {rm_e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao registar ficheiro na base de dados.")
    except Exception as e:
        session.rollback()
        logger.exception(f"User {user_id}: Erro inesperado ao salvar DB para '{safe_filename}': {e}")
        try:
            if os.path.exists(file_path): os.remove(file_path); logger.info(f"User {user_id}: Arquivo físico órfão removido: {file_path}")
        except OSError: pass
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado no registo do ficheiro.")

    return new_file, analysis

def get_files_query(session: Session):
    return session.query(File)

def get_file_by_id(session: Session, file_id: str) -> File:
    file = session.query(File).filter(File.id == file_id).first()
    if not file:
        logger.info(f"Tentativa de acesso a ficheiro não existente: ID {file_id}")
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return file

def get_file_by_hash(session: Session, file_hash: str) -> File | None:
    hash_file = session.query(File).filter(File.file_hash == file_hash).first()
    if not hash_file:
        logger.info(f"Tentativa de acesso a ficheiro não existente: Hash {file_hash}")
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return hash_file

def delete_file(session: Session, file_id: str):
    logger.info(f"Iniciando deleção do ficheiro ID: {file_id}")

    file = session.query(File).options(
        joinedload(File.analysis).joinedload(Analysis.streams)
    ).filter(File.id == file_id).first()

    if not file:
        logger.warning(f"Tentativa de deletar ficheiro {file_id} falhou: Não encontrado.")
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")

    file_path_to_delete = file.file_path
    filename_log = file.file_name
    
    stream_paths_to_delete = []
    if file.analysis: 
        for analysis in file.analysis:
            if analysis.streams:
                for stream in analysis.streams:
                    if stream.content_path:
                        stream_paths_to_delete.append(stream.content_path)
    
    logger.info(f"Ficheiro {file_id}: Coletados {len(stream_paths_to_delete)} caminhos de stream .bin para remoção.")

    try:
        session.delete(file)
        session.commit()
        logger.info(f"Registro DB do ficheiro {file_id} ('{filename_log}') deletado com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro DB ao deletar ficheiro {file_id} ('{filename_log}'): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro ao deletar registro do ficheiro.")

    try:
        if file_path_to_delete and os.path.exists(file_path_to_delete):
            os.remove(file_path_to_delete)
            logger.info(f"Ficheiro físico .pcap removido com sucesso: {file_path_to_delete}")
        elif file_path_to_delete:
            logger.warning(f"Registro DB {file_id} deletado, mas arquivo físico .pcap não encontrado: {file_path_to_delete}")
    except OSError as e:
        logger.warning(f"Erro OSError ao remover ficheiro físico .pcap {file_path_to_delete} (ID DB: {file_id}): {e}")
    except Exception as e:
        logger.warning(f"Erro inesperado ao remover ficheiro físico .pcap {file_path_to_delete} (ID DB: {file_id})", exc_info=True)

    deleted_streams_count = 0
    for path in stream_paths_to_delete:
        try:
            if path and os.path.exists(path):
                os.remove(path)
                deleted_streams_count += 1
        except OSError as e:
            logger.warning(f"Erro OSError ao remover ficheiro de stream {path} (ID DB: {file_id}): {e}")
    logger.info(f"Removidos {deleted_streams_count}/{len(stream_paths_to_delete)} arquivos .bin de stream.")


def get_safe_file_path(session: Session, file_id: str, current_user: User) -> Tuple[str, str]:
    logger.debug(f"User {current_user.id} solicitou download do file_id {file_id}")
    
    file = get_file_by_id(session, file_id)

    if file.user_id != current_user.id and not current_user.is_superuser:
        logger.warning(f"User {current_user.id} (não-admin) tentou baixar arquivo {file_id} do user {file.user_id}. Acesso negado.")
        raise HTTPException(status_code=403, detail="Sem permissão para baixar este ficheiro")

    try:
        file_path_from_db = file.file_path
        file_path_resolved = os.path.abspath(file_path_from_db)
        base_dir = os.path.abspath(UPLOAD_DIRECTORY)

        common_path = os.path.commonpath([file_path_resolved, base_dir])
        
        if not os.path.exists(file_path_resolved) or common_path != base_dir:
            logger.error(f"User {current_user.id} tentou baixar {file_id}, mas o caminho é inválido ou perigoso (Path Traversal?). Path: {file_path_resolved}")
            raise HTTPException(status_code=403, detail="Acesso ao ficheiro inválido ou não autorizado.")

    except Exception as e:
        logger.error(f"Erro na validação de segurança do caminho para file {file_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao validar caminho do ficheiro.")

    logger.info(f"User {current_user.id} autorizado a baixar {file_id} de {file_path_resolved}")
    return (file_path_resolved, file.file_name)

