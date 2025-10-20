import asyncio
import os
import traceback
import logging
from sqlalchemy.orm import sessionmaker
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
ingestion_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="ingestor_worker")

class IngestorEventHandler(FileSystemEventHandler):
    def __init__(self, user_id: str, app):
        super().__init__()
        self.user_id = user_id
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process(event.dest_path)

    def process(self, filepath: str):
        try:
            if filepath.endswith((".pcap", ".pcapng")):
                asyncio.run(asyncio.sleep(0.5)) 
                logger.info(f"Watchdog detectou: {filepath}. Submetendo para ingestão.")
                ingestion_executor.submit(_run_ingestion_sync, filepath, self.user_id, self.app)
        except Exception as e:
            logger.error(f"Erro no handler do watchdog ao processar {filepath}: {e}")


async def launch_background_ingestor(app):
    if hasattr(app.state, "ingestor_task") and app.state.ingestor_task:
        return
    
    app.state.current_observer = None
    app.state.current_watch_path = None
    app.state.current_watch_user_id = None
    
    loop = asyncio.get_running_loop()
    app.state.ingestor_task = loop.create_task(run_ingestor_loop(app))
    logger.info("Ingestor (Watchdog Manager) background task started.")


async def stop_background_ingestor(app):
    task = getattr(app.state, "ingestor_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.info("Ingestor manager background task cancelled.")
        except Exception:
            logger.exception("Error while stopping ingestor manager task.")
    
    observer = getattr(app.state, "current_observer", None)
    if observer:
        try:
            observer.stop()
            observer.join() 
            logger.info("Watchdog observer stopped.")
        except Exception:
            logger.exception("Error stopping watchdog observer.")
            
    ingestion_executor.shutdown(wait=True)
    logger.info("Ingestion executor shut down.")


async def run_ingestor_loop(app):
    logger.info("Entrando no loop gerenciador do ingestor (watchdog).")
    while True:
        try:
            folder_to_watch = None
            user_id_to_assign = None
            
            with SessionLocal() as session:
                folder_to_watch = settings_service.get_setting(session, settings_service.INGEST_FOLDER_KEY)
                user_id_to_assign = settings_service.get_setting(session, settings_service.INGEST_USER_ID_KEY)

            if folder_to_watch:
                folder_to_watch = os.path.abspath(folder_to_watch)

            observer = getattr(app.state, "current_observer", None)
            current_path = getattr(app.state, "current_watch_path", None)
            current_user = getattr(app.state, "current_watch_user_id", None)

            if folder_to_watch and user_id_to_assign:
                if not os.path.isdir(folder_to_watch):
                    logger.error(f"Pasta de ingestão {folder_to_watch} não existe ou não é um diretório.")
                    if observer:
                        observer.stop(); observer.join()
                        app.state.current_observer = None
                        app.state.current_watch_path = None
                        app.state.current_watch_user_id = None
                        
                elif folder_to_watch != current_path or user_id_to_assign != current_user:
                    logger.info(f"Configuração do ingestor mudou. Reiniciando watchdog...")
                    if observer:
                        observer.stop(); observer.join()
                    
                    event_handler = IngestorEventHandler(user_id=user_id_to_assign, app=app)
                    observer = Observer()
                    observer.schedule(event_handler, folder_to_watch, recursive=False)
                    observer.start()
                    
                    app.state.current_observer = observer
                    app.state.current_watch_path = folder_to_watch
                    app.state.current_watch_user_id = user_id_to_assign
                    logger.info(f"Watchdog iniciado e monitorando: {folder_to_watch}")
            
            elif (not folder_to_watch or not user_id_to_assign) and observer:
                logger.info("Configuração do ingestor removida. Parando watchdog.")
                observer.stop(); observer.join()
                app.state.current_observer = None
                app.state.current_watch_path = None
                app.state.current_watch_user_id = None

            await asyncio.sleep(INGEST_POLL_SECONDS)
        except asyncio.CancelledError:
            logger.info("Loop gerenciador do ingestor cancelado.")
            if getattr(app.state, "current_observer", None):
                app.state.current_observer.stop()
                app.state.current_observer.join()
            break
        except Exception:
            logger.exception("Erro inesperado no loop gerenciador do ingestor.")
            await asyncio.sleep(INGEST_POLL_SECONDS * 2)


def _run_ingestion_sync(filepath: str, user_id: str, app):
    if not os.path.isfile(filepath):
        logger.warn(f"Ficheiro {filepath} desapareceu antes do processamento.")
        return

    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        
        file_wrapper = UploadFile(filename=os.path.basename(filepath), file=BytesIO(file_data))
        
        with SessionLocal() as session:
            new_file, analysis = _create_file_sync(session, file_wrapper, user_id)
            process_pool = app.state.process_pool
            process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
            logging.getLogger("sharpshark.ingestor").info(f"Análise {analysis.id} submetida ao Process Pool a partir do Ingestor.")
            
            logger.info(f"Ficheiro ingerido com sucesso: {filepath}. Análise submetida.")
            os.remove(filepath)

    except HTTPException as e:
        if e.status_code in [400, 409, 413]:
            logger.warn(f"Falha ao ingerir {filepath}: {e.detail}. Removendo da pasta.")
            try:
                os.remove(filepath)
            except Exception as rm_e:
                logger.error(f"Não foi possível remover ficheiro inválido {filepath}: {rm_e}")
        else:
            logger.error(f"HTTPException ao processar {filepath}: {e.detail}. O ficheiro NÃO será removido.")
            
    except Exception as e:
        logger.exception(f"Erro crítico ao processar {filepath}: {e}. O ficheiro NÃO será removido.")
        traceback.print_exc()