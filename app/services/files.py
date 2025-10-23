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
from task_runner import run_analysis_task # Importa a função que será executada no Process Pool

UPLOAD_DIR = UPLOAD_DIRECTORY
MAX_UPLOAD_BYTES = 100 * 1024 * 1024 # Limite de 100 MB
logger = logging.getLogger("sharpshark.files")

async def create_file(session: Session, file: UploadFile, user_id: str, request: Request) -> File:
    """
    Função assíncrona (nível da API) para lidar com o upload de arquivos.
    Ela delega o trabalho pesado (I/O, hash, validação) para uma thread
    e depois submete a análise para um processo separado.
    """
    client_ip = request.client.host if request.client else "IP Desconhecido"
    logger.info(f"Recebida tentativa de upload de user {user_id} (IP: {client_ip})")

    # 1. Verifica o Rate Limiter de Upload (baseado no User ID)
    if not await upload_rate_limiter.is_allowed(user_id):
        logger.warning(f"User {user_id} (IP: {client_ip}) atingiu limite de upload.")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Limite de uploads atingido. Tente novamente mais tarde."
        )
    try:
        # 2. Executa a validação e salvamento do arquivo em uma thread separada
        # Isso evita bloquear o loop de eventos principal (asyncio) com I/O
        new_file, analysis = await asyncio.to_thread(_create_file_sync, session, file, user_id)

        # 3. Submete a tarefa de ANÁLISE (uso intensivo de CPU) para o Process Pool
        # 'app.state.process_pool' foi criado no main.py
        process_pool = request.app.state.process_pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logger.info(f"Análise {analysis.id} (Arquivo {new_file.id}) submetida ao Process Pool via API (User: {user_id}).")

        # 4. Retorna imediatamente para o usuário (a análise roda em background)
        return new_file
    
    except HTTPException as e:
        # Loga erros de validação (4xx) ou erros internos (5xx)
        if 400 <= e.status_code < 500:
            logger.info(f"Falha no upload para user {user_id} (IP: {client_ip}): {e.status_code} - {e.detail}")
        else:
            logger.error(f"Erro HTTP {e.status_code} inesperado durante upload (User: {user_id}, IP: {client_ip}): {e.detail}")
        raise e
    except Exception as e:
        logger.exception(f"Erro GERAL inesperado em create_file (User: {user_id}, IP: {client_ip}): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro interno inesperado ao iniciar processamento do ficheiro.")

def _create_file_sync(session: Session, file: UploadFile, user_id: str) -> tuple[File, Analysis]:
    """
    Função síncrona (worker) que faz todo o trabalho de validação e I/O.
    Esta função é executada em uma thread separada (via 'asyncio.to_thread').
    """
    filename_log = file.filename or "NomeDesconhecido"
    logger.info(f"User {user_id}: Iniciando _create_file_sync para '{filename_log}'")

    # Garante que o diretório de upload existe
    try: os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as e:
        logger.error(f"User {user_id}: Falha crítica ao acessar/criar diretório de upload {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao acessar armazenamento.")

    # --- Início das Validações ---
    # 1. Extensão do arquivo
    if not file.filename or not file.filename.endswith((".pcapng", ".pcap")):
        logger.info(f"User {user_id}: Upload rejeitado - Nome/extensão inválida '{filename_log}'")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nome de ficheiro inválido ou extensão não permitida (.pcapng, .pcap).")
    # 2. Header (Magic Number)
    try: validate_pcap_header(file)
    except HTTPException as e:
        logger.info(f"User {user_id}: Upload rejeitado - Header inválido '{filename_log}' - {e.detail}")
        raise e
    except Exception as e:
        logger.warning(f"User {user_id}: Erro inesperado validando header '{filename_log}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível ler o cabeçalho do ficheiro.")
    # 3. Tamanho do arquivo
    try:
        size_bytes = file.file.seek(0, 2) # Vai para o fim do arquivo
        file.file.seek(0) # Volta para o início
    except (OSError, AttributeError, ValueError) as e:
        logger.warning(f"User {user_id}: Erro ao determinar tamanho '{filename_log}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não foi possível determinar o tamanho do ficheiro.")
    
    if size_bytes > MAX_UPLOAD_BYTES:
        logger.info(f"User {user_id}: Upload rejeitado - Ficheiro muito grande '{filename_log}' ({size_bytes} bytes)")
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Ficheiro excede o limite máximo de {MAX_UPLOAD_BYTES / 1024 / 1024} MB")
    if size_bytes == 0:
        logger.info(f"User {user_id}: Upload rejeitado - Ficheiro vazio '{filename_log}'")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ficheiro vazio não permitido.")

    # 4. Hash (para evitar duplicados)
    try: file_hash = calculate_file_hash(file)
    except Exception as e:
        logger.error(f"User {user_id}: Erro calculando hash '{filename_log}': {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao processar hash do ficheiro.")
    
    existing = session.query(File.id).filter(File.file_hash == file_hash).first()
    if existing:
        logger.info(f"User {user_id}: Upload rejeitado - Hash duplicado '{file_hash}' ('{filename_log}')")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ficheiro com este conteúdo já foi registado anteriormente.")
    # --- Fim das Validações ---

    file_path = "N/A"
    try:
        # Cria um nome de arquivo seguro (sanitiza e adiciona timestamp)
        original_name, ext = os.path.splitext(os.path.basename(file.filename))
        clean_name = re.sub(r"[^\w\-.]", "_", original_name)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")[:-3]
        safe_filename = f"{clean_name}_{timestamp}{ext}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)

        # Salva o arquivo no disco
        with open(file_path, "wb") as buffer:
            file.file.seek(0)
            while chunk := file.file.read(8192): buffer.write(chunk)
            file.file.seek(0)
        logger.info(f"User {user_id}: Arquivo físico salvo: {file_path}")
    except OSError as e:
        logger.error(f"User {user_id}: Erro OSError ao salvar '{safe_filename}' em {UPLOAD_DIR}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao salvar ficheiro no servidor.")
    except Exception as e:
        # Se falhar ao salvar, remove o arquivo parcial (se existir)
        logger.exception(f"User {user_id}: Erro inesperado ao salvar '{filename_log}': {e}")
        if os.path.exists(file_path):
             try: os.remove(file_path); logger.info(f"User {user_id}: Arquivo parcial removido: {file_path}")
             except OSError: logger.warning(f"User {user_id}: Falha ao remover arquivo parcial {file_path}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado ao salvar ficheiro.")

    try:
        # --- Transação de Banco de Dados ---
        file_size_mb = size_bytes / 1024 / 1024
        
        # 1. Cria o registro do 'File'
        new_file = File(
            file_name=safe_filename, file_path=file_path, file_size=file_size_mb,
            file_hash=file_hash, user_id=user_id,
        )
        session.add(new_file)
        session.flush() # Força o 'new_file' a obter um ID
        
        # 2. Cria o registro da 'Analysis' associada, com status 'pending'
        analysis = Analysis(file_id=new_file.id, user_id=user_id, status="pending")
        session.add(analysis)
        
        # 3. Commita a transação (File e Analysis juntos)
        session.commit()
        session.refresh(new_file); session.refresh(analysis)
        logger.info(f"User {user_id}: Ficheiro {new_file.id} ({safe_filename}) e Análise {analysis.id} criados no DB.")
    
    except sqlalchemy_exc.SQLAlchemyError as e:
        # Se o DB falhar, remove o arquivo físico que ficou órfão
        session.rollback()
        logger.error(f"User {user_id}: Erro DB ao salvar registos ('{safe_filename}', Hash: {file_hash}): {e}")
        try:
            if os.path.exists(file_path): os.remove(file_path); logger.info(f"User {user_id}: Arquivo físico órfão removido: {file_path}")
        except OSError as rm_e: logger.warning(f"User {user_id}: Falha remover {file_path} órfão: {rm_e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno ao registar ficheiro na base de dados.")
    except Exception as e:
        # Se qualquer outra coisa falhar, remove o arquivo órfão
        session.rollback()
        logger.exception(f"User {user_id}: Erro inesperado ao salvar DB para '{safe_filename}': {e}")
        try:
             if os.path.exists(file_path): os.remove(file_path); logger.info(f"User {user_id}: Arquivo físico órfão removido: {file_path}")
        except OSError: pass
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno inesperado no registo do ficheiro.")

    return new_file, analysis

def get_files_query(session: Session):
    """ Retorna o objeto Query para arquivos (usado para paginação). """
    return session.query(File)

def get_file_by_id(session: Session, file_id: str) -> File:
    """ Busca um arquivo pelo ID. Falha com 404 se não encontrado. """
    file = session.query(File).filter(File.id == file_id).first()
    if not file:
        logger.info(f"Tentativa de acesso a ficheiro não existente: ID {file_id}")
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return file

def get_file_by_hash(session: Session, file_hash: str) -> File | None:
    """ Busca um arquivo pelo Hash. Falha com 404 se não encontrado. """
    hash_file = session.query(File).filter(File.file_hash == file_hash).first()
    if not hash_file:
        logger.info(f"Tentativa de acesso a ficheiro não existente: Hash {file_hash}")
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
    return hash_file

def delete_file(session: Session, file_id: str):
    """ Deleta um arquivo (registro do DB e arquivo físico). """
    logger.info(f"Iniciando deleção do ficheiro ID: {file_id}")
    file = get_file_by_id(session, file_id) # Busca (ou falha com 404)
    file_path_to_delete = file.file_path
    filename_log = file.file_name

    try:
        # 1. Deleta o registro do banco de dados
        # (Cascade delete irá deletar Analysis, Streams, Alerts, etc. associados)
        session.delete(file)
        session.commit()
        logger.info(f"Registro DB do ficheiro {file_id} ('{filename_log}') deletado com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Erro DB ao deletar ficheiro {file_id} ('{filename_log}'): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro ao deletar registro do ficheiro.")

    try:
        # 2. Deleta o arquivo físico (.pcap) do disco
        if file_path_to_delete and os.path.exists(file_path_to_delete):
            os.remove(file_path_to_delete)
            logger.info(f"Ficheiro físico removido com sucesso: {file_path_to_delete}")
        elif file_path_to_delete:
             logger.warning(f"Registro DB {file_id} deletado, mas arquivo físico não encontrado: {file_path_to_delete}")
    except OSError as e:
        # Loga um aviso, mas não levanta exceção (o registro do DB já foi removido)
        logger.warning(f"Erro OSError ao remover ficheiro físico {file_path_to_delete} (ID DB: {file_id}): {e}")
    except Exception as e:
        logger.warning(f"Erro inesperado ao remover ficheiro físico {file_path_to_delete} (ID DB: {file_id})", exc_info=True)