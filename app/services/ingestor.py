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
from services.files import _create_file_sync
from task_runner import run_analysis_task
import services.settings as settings_service

logger = logging.getLogger("sharpshark.ingestor")
SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

INGEST_POLL_SECONDS = 15.0

ingestion_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingestor_worker")

class IngestorEventHandler(FileSystemEventHandler):
    def __init__(self, user_id: str, app):
        super().__init__()
        self.user_id = user_id
        self.app = app
        logger.debug(f"Handler Watchdog inicializado para User: {self.user_id}")

    def on_created(self, event):
        if not event.is_directory:
            logger.debug(f"Watchdog (User: {self.user_id}): Evento 'created' detectado: {event.src_path}")
            self.process(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            logger.debug(f"Watchdog (User: {self.user_id}): Evento 'moved' detectado: {event.dest_path}")
            self.process(event.dest_path)

    def process(self, filepath: str):
        try:
            if filepath.lower().endswith((".pcap", ".pcapng")):
                time.sleep(1.0)
                logger.info(f"Watchdog (User: {self.user_id}): Ficheiro PCAP válido detectado: {filepath}. Submetendo para ingestão.")
                ingestion_executor.submit(_run_ingestion_sync, filepath, self.user_id, self.app)
            else:
                 logger.debug(f"Watchdog (User: {self.user_id}): Ignorando ficheiro não PCAP: {filepath}")
        except Exception as e:
            logger.error(f"Watchdog (User: {self.user_id}): Erro no handler ao processar {filepath}: {e}", exc_info=True)


async def launch_background_ingestor(app):
    if hasattr(app.state, "ingestor_task") and app.state.ingestor_task and not app.state.ingestor_task.done():
        logger.info("Task gerenciadora do ingestor já está rodando.")
        return

    logger.info("Iniciando task gerenciadora do ingestor (Watchdog Manager)...")
    app.state.current_observer = None
    app.state.current_watch_path = None
    app.state.current_watch_user_id = None

    loop = asyncio.get_running_loop()
    app.state.ingestor_task = loop.create_task(run_ingestor_loop(app))
    logger.info("Task gerenciadora do ingestor iniciada.")


async def stop_background_ingestor(app):
    logger.info("Parando task gerenciadora do ingestor...")
    task = getattr(app.state, "ingestor_task", None)
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

    logger.info("Parando observer do Watchdog (se existir)...")
    observer = getattr(app.state, "current_observer", None)
    if observer and observer.is_alive():
        try:
            observer.stop()
            observer.join(timeout=5.0)
            if observer.is_alive():
                logger.warning("Timeout ao esperar observer do Watchdog parar.")
            else:
                logger.info("Observer do Watchdog parado com sucesso.")
        except Exception as e:
            logger.exception(f"Erro ao parar observer do Watchdog: {e}")
    else:
        logger.info("Observer do Watchdog não estava rodando.")

    logger.info("Encerrando executor de ingestão (aguardando tarefas pendentes)...")
    ingestion_executor.shutdown(wait=True)
    logger.info("Executor de ingestão encerrado.")


async def run_ingestor_loop(app):
    logger.info("Loop gerenciador do ingestor (Watchdog) iniciado.")
    while True:
        try:
            folder_to_watch = None
            user_id_to_assign = None
            session: Session = SessionLocal()

            try:
                folder_to_watch = settings_service.get_setting(session, settings_service.INGEST_FOLDER_KEY)
                user_id_to_assign = settings_service.get_setting(session, settings_service.INGEST_USER_ID_KEY)
            except sqlalchemy_exc.SQLAlchemyError as e:
                logger.error(f"Loop Ingestor: Erro DB ao buscar configurações: {e}")
            finally:
                session.close()

            if folder_to_watch: folder_to_watch = os.path.abspath(folder_to_watch)

            observer = getattr(app.state, "current_observer", None)
            current_path = getattr(app.state, "current_watch_path", None)
            current_user = getattr(app.state, "current_watch_user_id", None)

            if folder_to_watch and user_id_to_assign:
                if not os.path.isdir(folder_to_watch):
                    logger.error(f"Loop Ingestor: Pasta de ingestão configurada '{folder_to_watch}' não existe ou não é diretório. Watchdog não iniciado/parado.")
                    if observer and observer.is_alive():
                        logger.info("Parando observer devido à pasta inválida...")
                        observer.stop(); observer.join()
                        app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
                elif folder_to_watch != current_path or user_id_to_assign != current_user:
                    logger.info(f"Loop Ingestor: Configuração mudou (ou iniciando). Path: '{folder_to_watch}', User: '{user_id_to_assign}'. Reiniciando Watchdog...")
                    if observer and observer.is_alive():
                        observer.stop(); observer.join()
                    try:
                        event_handler = IngestorEventHandler(user_id=user_id_to_assign, app=app)
                        observer = Observer()
                        observer.schedule(event_handler, folder_to_watch, recursive=False)
                        observer.start()
                        app.state.current_observer = observer
                        app.state.current_watch_path = folder_to_watch
                        app.state.current_watch_user_id = user_id_to_assign
                        logger.info(f"Watchdog iniciado e monitorando: {folder_to_watch}")
                    except Exception as e:
                         logger.exception(f"Loop Ingestor: Falha CRÍTICA ao iniciar Watchdog para '{folder_to_watch}': {e}")
                         app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
            elif observer and observer.is_alive():
                logger.info("Loop Ingestor: Configuração de ingestão removida ou incompleta. Parando Watchdog.")
                observer.stop(); observer.join()
                app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None

            await asyncio.sleep(INGEST_POLL_SECONDS)

        except asyncio.CancelledError:
            logger.info("Loop gerenciador do ingestor cancelado.")
            break
        except Exception as e:
            logger.exception(f"Loop Ingestor: Erro inesperado no ciclo: {e}")
            await asyncio.sleep(INGEST_POLL_SECONDS * 2)


def _run_ingestion_sync(filepath: str, user_id: str, app):
    if not os.path.isfile(filepath):
        logger.warning(f"Ingestor Worker (User: {user_id}): Ficheiro {filepath} desapareceu antes do processamento.")
        return

    logger.info(f"Ingestor Worker (User: {user_id}): Iniciando ingestão de {filepath}")
    session: Session = SessionLocal()
    file_processed = False
    try:
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
        except OSError as e:
            logger.error(f"Ingestor Worker (User: {user_id}): Erro OSError ao ler {filepath}: {e}")
            return

        file_wrapper = UploadFile(filename=os.path.basename(filepath), file=BytesIO(file_data))
        new_file, analysis = _create_file_sync(session, file_wrapper, user_id)

        file_processed = True
        process_pool = app.state.process_pool
        process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
        logger.info(f"Ingestor Worker (User: {user_id}): Análise {analysis.id} (Arq: {new_file.id}) submetida ao Pool.")
        logger.info(f"Ingestor Worker (User: {user_id}): Ingestão de {filepath} bem-sucedida. Removendo original.")
        try:
            os.remove(filepath)
        except OSError as e:
             logger.warning(f"Ingestor Worker (User: {user_id}): Falha ao remover arquivo original {filepath} após ingestão: {e}")

    except HTTPException as e:
        if e.status_code in [400, 409, 413]:
            logger.warning(f"Ingestor Worker (User: {user_id}): Falha ao ingerir {filepath}: {e.detail}. Removendo.")
            try: os.remove(filepath)
            except Exception as rm_e: logger.error(f"Ingestor Worker (User: {user_id}): Falha CRÍTICA ao remover ficheiro inválido {filepath}: {rm_e}")
        else:
            logger.error(f"Ingestor Worker (User: {user_id}): HTTPException {e.status_code} ao processar {filepath}: {e.detail}. NÃO será removido.")
    except Exception as e:
        logger.exception(f"Ingestor Worker (User: {user_id}): Erro crítico ao processar {filepath}: {e}. NÃO será removido.")
    finally:
        session.close()