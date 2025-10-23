import asyncio
import os
import traceback
import logging
import time
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import exc as sqlalchemy_exc
from db.models import db
from fastapi import UploadFile, HTTPException
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from services.files import _create_file_sync # Reutiliza a lógica de criação de arquivo
from task_runner import run_analysis_task
import services.settings as settings_service

logger = logging.getLogger("sharpshark.ingestor")
SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

INGEST_POLL_SECONDS = 15.0 # Tempo que o loop gerenciador dorme

# Thread Pool para tarefas do *Ingestor* (ler arquivo, chamar _create_file_sync)
# É separado do Process Pool principal (que faz a análise pesada)
ingestion_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingestor_worker")

class IngestorEventHandler(FileSystemEventHandler):
    """
    Handler do Watchdog. É acionado quando o S.O. detecta
    criação ou movimentação de arquivos na pasta monitorada.
    """
    def __init__(self, user_id: str, app):
        super().__init__()
        self.user_id = user_id # O ID do usuário (definido nas Configs) a quem o arquivo será atribuído
        self.app = app # Referência à app FastAPI (para acessar o Process Pool)
        logger.debug(f"Handler Watchdog inicializado para User: {self.user_id}")

    def on_created(self, event):
        """ Chamado quando um arquivo é criado. """
        if not event.is_directory:
            logger.debug(f"Watchdog (User: {self.user_id}): Evento 'created' detectado: {event.src_path}")
            self.process(event.src_path)

    def on_moved(self, event):
        """ Chamado quando um arquivo é movido/renomeado para a pasta. """
        if not event.is_directory:
            logger.debug(f"Watchdog (User: {self.user_id}): Evento 'moved' detectado: {event.dest_path}")
            self.process(event.dest_path)

    def process(self, filepath: str):
        """
        Filtra o evento e submete a tarefa de ingestão para o ThreadPool do Ingestor.
        """
        try:
            # Verifica se é um arquivo PCAP
            if filepath.lower().endswith((".pcap", ".pcapng")):
                time.sleep(1.0) # Pequena espera para garantir que o arquivo terminou de ser copiado
                logger.info(f"Watchdog (User: {self.user_id}): Ficheiro PCAP válido detectado: {filepath}. Submetendo para ingestão.")
                # Submete a tarefa de ingestão (I/O) para o ThreadPool
                ingestion_executor.submit(_run_ingestion_sync, filepath, self.user_id, self.app)
            else:
                logger.debug(f"Watchdog (User: {self.user_id}): Ignorando ficheiro não PCAP: {filepath}")
        except Exception as e:
            logger.error(f"Watchdog (User: {self.user_id}): Erro no handler ao processar {filepath}: {e}", exc_info=True)


async def launch_background_ingestor(app):
    """
    Inicia a task de background (asyncio) que gerencia o Watchdog.
    Chamado no 'startup' do FastAPI.
    """
    if hasattr(app.state, "ingestor_task") and app.state.ingestor_task and not app.state.ingestor_task.done():
        logger.info("Task gerenciadora do ingestor já está rodando.")
        return

    logger.info("Iniciando task gerenciadora do ingestor (Watchdog Manager)...")
    # Inicializa o estado
    app.state.current_observer = None
    app.state.current_watch_path = None
    app.state.current_watch_user_id = None

    loop = asyncio.get_running_loop()
    # Cria a task que rodará o 'run_ingestor_loop'
    app.state.ingestor_task = loop.create_task(run_ingestor_loop(app))
    logger.info("Task gerenciadora do ingestor iniciada.")


async def stop_background_ingestor(app):
    """
    Para a task de background (asyncio) e o Watchdog.
    Chamado no 'shutdown' do FastAPI.
    """
    logger.info("Parando task gerenciadora do ingestor...")
    task = getattr(app.state, "ingestor_task", None)
    # 1. Cancela a task asyncio
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.info("Task gerenciadora do ingestor cancelada com sucesso.")
        except Exception as e:
            logger.exception(f"Erro ao aguardar cancelamento da task gerenciadora: {e}")
    else:
        logger.info("Task gerenciadora do ingestor não estava rodando ou já havia terminado.")

    # 2. Para o 'observer' (Watchdog)
    logger.info("Parando observer do Watchdog (se existir)...")
    observer = getattr(app.state, "current_observer", None)
    if observer and observer.is_alive():
        try:
            observer.stop()
            observer.join(timeout=5.0) # Espera a thread do watchdog terminar
            if observer.is_alive():
                logger.warning("Timeout ao esperar observer do Watchdog parar.")
            else:
                logger.info("Observer do Watchdog parado com sucesso.")
        except Exception as e:
            logger.exception(f"Erro ao parar observer do Watchdog: {e}")
    else:
        logger.info("Observer do Watchdog não estava rodando.")

    # 3. Encerra o ThreadPool do Ingestor
    logger.info("Encerrando executor de ingestão (aguardando tarefas pendentes)...")
    ingestion_executor.shutdown(wait=True)
    logger.info("Executor de ingestão encerrado.")


async def run_ingestor_loop(app):
    """
    A task de background (asyncio) que gerencia o Watchdog.
    Ela verifica o banco de dados periodicamente para ver se as
    configurações de ingestão mudaram.
    """
    logger.info("Loop gerenciador do ingestor (Watchdog) iniciado.")
    while True:
        try:
            folder_to_watch = None
            user_id_to_assign = None
            session: Session = SessionLocal() # Cria uma sessão curta para ler configs

            # 1. Lê as configurações atuais do DB
            try:
                folder_to_watch = settings_service.get_setting(session, settings_service.INGEST_FOLDER_KEY)
                user_id_to_assign = settings_service.get_setting(session, settings_service.INGEST_USER_ID_KEY)
            except sqlalchemy_exc.SQLAlchemyError as e:
                logger.error(f"Loop Ingestor: Erro DB ao buscar configurações: {e}")
            finally:
                session.close()

            if folder_to_watch: folder_to_watch = os.path.abspath(folder_to_watch)

            # Pega o estado atual do observer (salvo no 'app.state')
            observer = getattr(app.state, "current_observer", None)
            current_path = getattr(app.state, "current_watch_path", None)
            current_user = getattr(app.state, "current_watch_user_id", None)

            # 2. Lógica de decisão
            if folder_to_watch and user_id_to_assign:
                # Caso A: Configs existem, mas a pasta não é válida
                if not os.path.isdir(folder_to_watch):
                    logger.error(f"Loop Ingestor: Pasta de ingestão configurada '{folder_to_watch}' não existe ou não é diretório. Watchdog não iniciado/parado.")
                    if observer and observer.is_alive():
                        logger.info("Parando observer devido à pasta inválida...")
                        observer.stop(); observer.join()
                        app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
                # Caso B: Configs mudaram (ou é a primeira vez)
                elif folder_to_watch != current_path or user_id_to_assign != current_user:
                    logger.info(f"Loop Ingestor: Configuração mudou (ou iniciando). Path: '{folder_to_watch}', User: '{user_id_to_assign}'. Reiniciando Watchdog...")
                    if observer and observer.is_alive():
                        observer.stop(); observer.join() # Para o antigo
                    try:
                        # Inicia o novo observer
                        event_handler = IngestorEventHandler(user_id=user_id_to_assign, app=app)
                        observer = Observer()
                        observer.schedule(event_handler, folder_to_watch, recursive=False)
                        observer.start()
                        # Salva o novo estado
                        app.state.current_observer = observer
                        app.state.current_watch_path = folder_to_watch
                        app.state.current_watch_user_id = user_id_to_assign
                        logger.info(f"Watchdog iniciado e monitorando: {folder_to_watch}")
                    except Exception as e:
                         logger.exception(f"Loop Ingestor: Falha CRÍTICA ao iniciar Watchdog para '{folder_to_watch}': {e}")
                         app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
            # Caso C: Configs foram limpas (pasta ou usuário vazios)
            elif observer and observer.is_alive():
                logger.info("Loop Ingestor: Configuração de ingestão removida ou incompleta. Parando Watchdog.")
                observer.stop(); observer.join()
                app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None

            # 3. Dorme antes de verificar novamente
            await asyncio.sleep(INGEST_POLL_SECONDS)

        except asyncio.CancelledError:
            logger.info("Loop gerenciador do ingestor cancelado.")
            break
        except Exception as e:
            logger.exception(f"Loop Ingestor: Erro inesperado no ciclo: {e}")
            await asyncio.sleep(INGEST_POLL_SECONDS * 2) # Espera mais se der erro


def _run_ingestion_sync(filepath: str, user_id: str, app):
    """
    Função worker (síncrona) executada no ThreadPool do Ingestor.
    Ela simula um upload de API.
    """
    if not os.path.isfile(filepath):
        logger.warning(f"Ingestor Worker (User: {user_id}): Ficheiro {filepath} desapareceu antes do processamento.")
        return

    logger.info(f"Ingestor Worker (User: {user_id}): Iniciando ingestão de {filepath}")
    session: Session = SessionLocal() # Cria uma sessão DB para esta thread
    file_processed = False
    try:
        # 1. Lê o arquivo do disco
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
        except OSError as e:
            logger.error(f"Ingestor Worker (User: {user_id}): Erro OSError ao ler {filepath}: {e}")
            return

        # 2. Simula um 'UploadFile' do FastAPI
        file_wrapper = UploadFile(filename=os.path.basename(filepath), file=BytesIO(file_data))
        
        # 3. Chama a *mesma* função de criação/validação da API
        new_file, analysis = _create_file_sync(session, file_wrapper, user_id)

        file_processed = True
        
        # 4. Pega o Process Pool *principal* (do app.state)
        process_pool = app.state.process_pool
        
        # 5. Submete a análise pesada (CPU) para o Process Pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logger.info(f"Ingestor Worker (User: {user_id}): Análise {analysis.id} (Arq: {new_file.id}) submetida ao Pool.")
        
        # 6. (Sucesso) Remove o arquivo original da pasta de ingestão
        logger.info(f"Ingestor Worker (User: {user_id}): Ingestão de {filepath} bem-sucedida. Removendo original.")
        try:
            os.remove(filepath)
        except OSError as e:
             logger.warning(f"Ingestor Worker (User: {user_id}): Falha ao remover arquivo original {filepath} após ingestão: {e}")

    except HTTPException as e:
        # Se _create_file_sync falhar (ex: duplicado, inválido), remove o arquivo
        if e.status_code in [400, 409, 413]: # Bad Request, Conflict, Too Large
            logger.warning(f"Ingestor Worker (User: {user_id}): Falha ao ingerir {filepath}: {e.detail}. Removendo.")
            try: os.remove(filepath)
            except Exception as rm_e: logger.error(f"Ingestor Worker (User: {user_id}): Falha CRÍTICA ao remover ficheiro inválido {filepath}: {rm_e}")
        else:
            # Outros erros (ex: 500) - não remove o arquivo
            logger.error(f"Ingestor Worker (User: {user_id}): HTTPException {e.status_code} ao processar {filepath}: {e.detail}. NÃO será removido.")
    except Exception as e:
        # Erro inesperado - não remove o arquivo
        logger.exception(f"Ingestor Worker (User: {user_id}): Erro crítico ao processar {filepath}: {e}. NÃO será removido.")
    finally:
        session.close() # Fecha a sessão desta thread