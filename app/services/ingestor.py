import asyncio
import os
import logging
import time
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import exc as sqlalchemy_exc
from db.models import db
from fastapi import UploadFile, HTTPException
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
from threading import Timer
from services.files import _create_file_sync
from task_runner import run_analysis_task
from services.settings import get_setting, INGEST_FOLDER_KEY, INGEST_USER_ID_KEY
from core.config import INGEST_BASE_DIRECTORY

logger = logging.getLogger("sharpshark.ingestor")
SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

INGEST_POLL_SECONDS = 15.0
STABILITY_CHECK_INTERVAL_SECONDS = 10.0
REQUIRED_STABLE_CHECKS = 2
MAX_VERIFICATION_DURATION_SECONDS = 1800
REPROCESS_ALLOW_DELAY_SECONDS = 30.0


ingestion_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingestor_worker")

class IngestorEventHandler(FileSystemEventHandler):
    def __init__(self, user_id: str, app):
        super().__init__()
        self.user_id = user_id
        self.app = app
        logger.debug(f"Handler Watchdog inicializado para User: {self.user_id}")
        self._scheduled_recently = set()

    def _remove_from_scheduled(self, filepath: str):
        self._scheduled_recently.discard(filepath)
        logger.debug(f"Watchdog: Permitindo nova detecção para {filepath}")

    def _schedule_processing(self, filepath: str):
        abs_path = os.path.abspath(filepath)
        if abs_path in self._scheduled_recently:
            logger.debug(f"Watchdog: Ignorando evento para {abs_path} (já agendado recentemente).")
            return

        logger.info(f"Watchdog (User: {self.user_id}): Ficheiro PCAP detectado: {abs_path}. Agendando worker de ingestão.")
        self._scheduled_recently.add(abs_path)
        ingestion_executor.submit(_run_ingestion_sync, abs_path, self.user_id, self.app)
        Timer(REPROCESS_ALLOW_DELAY_SECONDS, self._remove_from_scheduled, [abs_path]).start()

    def on_created(self, event):
        if event.is_directory: return
        filepath = event.src_path
        logger.debug(f"Watchdog (User: {self.user_id}): Evento 'created' detectado para: {filepath}")
        if filepath.lower().endswith((".pcap", ".pcapng")):
            self._schedule_processing(filepath)

    def on_moved(self, event):
        if event.is_directory: return
        filepath = event.dest_path
        logger.debug(f"Watchdog (User: {self.user_id}): Evento 'moved' detectado para: {filepath}")
        if filepath.lower().endswith((".pcap", ".pcapng")):
            self._schedule_processing(filepath)

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
        try: await task
        except asyncio.CancelledError: logger.info("Task gerenciadora do ingestor cancelada com sucesso.")
        except Exception as e: logger.exception(f"Erro ao aguardar cancelamento da task gerenciadora: {e}")
    else: logger.info("Task gerenciadora do ingestor não estava rodando ou já havia terminado.")

    logger.info("Parando observer do Watchdog (se existir)...")
    observer = getattr(app.state, "current_observer", None)
    if observer and observer.is_alive():
        try:
            observer.stop()
            observer.join(timeout=5.0)
            if observer.is_alive(): logger.warning("Timeout ao esperar observer do Watchdog parar.")
            else: logger.info("Observer do Watchdog parado com sucesso.")
        except Exception as e: logger.exception(f"Erro ao parar observer do Watchdog: {e}")
    else: logger.info("Observer do Watchdog não estava rodando.")

    logger.info("Encerrando executor de ingestão (aguardando tarefas pendentes)...")
    ingestion_executor.shutdown(wait=True)
    logger.info("Executor de ingestão encerrado.")


def _scan_and_schedule_existing_files(folder_path: str, user_id: str, app):
    logger.info(f"Scanner: Verificando arquivos PCAP existentes em {folder_path}...")
    try:
        count = 0
        for filename in os.listdir(folder_path):
            if filename.lower().endswith((".pcap", ".pcapng")):
                filepath = os.path.join(folder_path, filename)
                temp_handler = IngestorEventHandler(user_id=user_id, app=app)
                logger.debug(f"Scanner: Encontrado arquivo existente: {filepath}. Agendando...")
                temp_handler._schedule_processing(filepath)
                count += 1
        logger.info(f"Scanner: {count} arquivos existentes agendados para verificação.")
    except FileNotFoundError:
        logger.error(f"Scanner: Pasta não encontrada durante scan inicial: {folder_path}")
    except OSError as e:
        logger.error(f"Scanner: Erro OSError ao listar arquivos em {folder_path}: {e}")
    except Exception as e:
        logger.exception(f"Scanner: Erro inesperado durante scan inicial: {e}")


async def run_ingestor_loop(app):
    logger.info("Loop gerenciador do ingestor (Watchdog) iniciado.")
    initial_scan_done_for_path = {}

    while True:
        try:
            project_name_to_watch = None
            user_id_to_assign = None
            session: Session = SessionLocal()
            try:
                project_name_to_watch = get_setting(session, INGEST_FOLDER_KEY)
                user_id_to_assign = get_setting(session, INGEST_USER_ID_KEY)
            except sqlalchemy_exc.SQLAlchemyError as e: 
                logger.error(f"Loop Ingestor: Erro DB: {e}")
            finally: 
                session.close()

            folder_to_watch = None
            if project_name_to_watch:
                folder_to_watch = os.path.abspath(os.path.join(INGEST_BASE_DIRECTORY, project_name_to_watch))

            observer = getattr(app.state, "current_observer", None)
            current_path = getattr(app.state, "current_watch_path", None)
            current_user = getattr(app.state, "current_watch_user_id", None)

            if folder_to_watch and user_id_to_assign:
                if not os.path.isdir(folder_to_watch):
                    logger.error(f"Loop Ingestor: Pasta '{folder_to_watch}' inválida (Projeto: {project_name_to_watch}). Watchdog parado/não iniciado.")
                    if observer and observer.is_alive():
                        observer.stop(); observer.join()
                        app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
                        initial_scan_done_for_path.pop(folder_to_watch, None)

                elif folder_to_watch != current_path or user_id_to_assign != current_user:
                    logger.info(f"Loop Ingestor: Config mudou/iniciando. Path: '{folder_to_watch}', User: '{user_id_to_assign}'. (Re)Iniciando Watchdog...")
                    if observer and observer.is_alive(): observer.stop(); observer.join()
                    try:
                        event_handler = IngestorEventHandler(user_id=user_id_to_assign, app=app)
                        observer = Observer()
                        observer.schedule(event_handler, folder_to_watch, recursive=False)
                        observer.start()
                        app.state.current_observer = observer
                        app.state.current_watch_path = folder_to_watch
                        app.state.current_watch_user_id = user_id_to_assign
                        logger.info(f"Watchdog iniciado e monitorando: {folder_to_watch}")

                        if not initial_scan_done_for_path.get(folder_to_watch, False):
                            logger.info(f"Loop Ingestor: Executando scan inicial para pasta {folder_to_watch}")
                            _scan_and_schedule_existing_files(folder_to_watch, user_id_to_assign, app)
                            initial_scan_done_for_path[folder_to_watch] = True
                        else:
                            logger.debug(f"Loop Ingestor: Scan inicial já realizado para {folder_to_watch}. Pulando.")

                    except Exception as e:
                        logger.exception(f"Loop Ingestor: Falha CRÍTICA ao iniciar Watchdog: {e}")
                        app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
                        initial_scan_done_for_path.pop(folder_to_watch, None)

            elif observer and observer.is_alive():
                logger.info("Loop Ingestor: Configuração desativada. Parando Watchdog.")
                observer.stop(); observer.join()
                previous_path = app.state.current_watch_path
                app.state.current_observer = None; app.state.current_watch_path = None; app.state.current_watch_user_id = None
                if previous_path: initial_scan_done_for_path.pop(previous_path, None)

            await asyncio.sleep(INGEST_POLL_SECONDS)

        except asyncio.CancelledError: logger.info("Loop gerenciador do ingestor cancelado."); break
        except Exception as e: logger.exception(f"Loop Ingestor: Erro: {e}"); await asyncio.sleep(INGEST_POLL_SECONDS * 2)

def _run_ingestion_sync(filepath: str, user_id: str, app):
    worker_start_time = time.time()
    logger.info(f"Ingestor Worker (User: {user_id}): Iniciando verificação de estabilidade para {filepath}...")

    last_size = -1
    stable_checks_count = 0
    is_stable = False

    try:
        while True:
            current_duration = time.time() - worker_start_time
            if current_duration > MAX_VERIFICATION_DURATION_SECONDS:
                logger.warning(f"Ingestor Worker (User: {user_id}): Timeout ({MAX_VERIFICATION_DURATION_SECONDS}s) atingido ao verificar {filepath}. Pulando.")
                return

            current_size = -1
            try:
                if not os.path.exists(filepath):
                    logger.warning(f"Ingestor Worker (User: {user_id}): Ficheiro {filepath} desapareceu durante verificação.")
                    return
                current_size = os.path.getsize(filepath)
            except OSError as e:
                logger.error(f"Ingestor Worker (User: {user_id}): Erro OSError ao obter tamanho de {filepath}: {e}. Tentando novamente em {STABILITY_CHECK_INTERVAL_SECONDS}s...")
                stable_checks_count = 0
                last_size = -1
                time.sleep(STABILITY_CHECK_INTERVAL_SECONDS)
                continue

            logger.debug(f"Ingestor Worker: Verificando {filepath}. Tamanho: {current_size} bytes (anterior: {last_size}). Checks estáveis: {stable_checks_count}/{REQUIRED_STABLE_CHECKS}.")

            if last_size != -1 and current_size == last_size:
                stable_checks_count += 1
            else:
                stable_checks_count = 0

            last_size = current_size

            if stable_checks_count >= REQUIRED_STABLE_CHECKS and last_size > 0:
                logger.info(f"Ingestor Worker (User: {user_id}): Ficheiro {filepath} considerado estável ({last_size} bytes) após {stable_checks_count+1} verificações iguais consecutivas. Iniciando ingestão...")
                is_stable = True
                break

            logger.debug(f"Ingestor Worker: {filepath} ainda instável ou vazio. Aguardando {STABILITY_CHECK_INTERVAL_SECONDS}s...")
            time.sleep(STABILITY_CHECK_INTERVAL_SECONDS)

        if is_stable and last_size > 0:
            session: Session = SessionLocal()
            try:
                logger.debug(f"Ingestor Worker: Lendo {last_size} bytes de {filepath}...")
                try:
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    if len(file_data) != last_size:
                        logger.error(f"Ingestor Worker (User: {user_id}): Tamanho lido ({len(file_data)}) INCONSISTENTE com tamanho estável ({last_size}) para {filepath}! Abortando.")
                        return
                except OSError as e:
                    logger.error(f"Ingestor Worker (User: {user_id}): Erro OSError ao LER {filepath} após estabilização: {e}")
                    return

                logger.debug(f"Ingestor Worker: Simulando UploadFile para {filepath}...")
                file_wrapper = UploadFile(filename=os.path.basename(filepath), file=BytesIO(file_data))

                logger.debug(f"Ingestor Worker: Chamando _create_file_sync para {filepath}...")
                new_file, analysis = _create_file_sync(session, file_wrapper, user_id)
                logger.info(f"Ingestor Worker: Registros DB criados para {filepath} (File ID: {new_file.id}, Analysis ID: {analysis.id}).")

                logger.debug(f"Ingestor Worker: Submetendo análise {analysis.id} para o Process Pool...")
                process_pool = app.state.process_pool
                process_pool.submit(run_analysis_task, analysis_id=analysis.id, file_id=new_file.id)
                logger.info(f"Ingestor Worker (User: {user_id}): Análise {analysis.id} (Arq: {new_file.id}) submetida.")

                logger.info(f"Ingestor Worker (User: {user_id}): Ingestão de {filepath} completa. Removendo original da pasta ingest.")
                try:
                    os.remove(filepath)
                except OSError as e:
                    logger.warning(f"Ingestor Worker (User: {user_id}): Falha ao remover {filepath} da pasta ingest após sucesso: {e}")

            except HTTPException as e_sync:
                logger.warning(f"Ingestor Worker (User: {user_id}): Falha controlada ({e_sync.status_code}: {e_sync.detail}) ao processar {filepath}.")
                if e_sync.status_code in [400, 409, 413]:
                    logger.info(f"Ingestor Worker: Removendo arquivo inválido/duplicado/grande da pasta ingest: {filepath}")
                    try:
                        if os.path.exists(filepath): os.remove(filepath)
                    except Exception as rm_e:
                        logger.error(f"Ingestor Worker (User: {user_id}): Falha CRÍTICA ao remover ficheiro inválido {filepath}: {rm_e}")

            except Exception as e_general:
                logger.exception(f"Ingestor Worker (User: {user_id}): Erro crítico inesperado durante ingestão de {filepath}: {e_general}. Arquivo NÃO será removido.")

            finally:
                if 'session' in locals() and session:
                    session.close()

    except Exception as e_outer:
        logger.exception(f"Ingestor Worker (User: {user_id}): Erro irrecuperável (ex: loop de verificação) processando {filepath}: {e_outer}")