import asyncio
import traceback
from sqlalchemy.orm import sessionmaker
from db.models import db, Analysis, File
import logging

logger = logging.getLogger("sharpshark.worker")
SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

WORKER_POLL_SECONDS = 1.0

async def launch_background_worker(app):
    if hasattr(app.state, "worker_task") and app.state.worker_task:
        return
    loop = asyncio.get_running_loop()
    app.state.worker_task = loop.create_task(run_worker_loop())
    logger.info("Worker background task started.")

async def stop_background_worker(app):
    task = getattr(app.state, "worker_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.info("Worker background task cancelled.")
        except Exception:
            logger.exception("Error while stopping worker task.")
        app.state.worker_task = None

async def run_worker_loop():
    logger.info("Entering worker loop.")
    while True:
        try:
            with SessionLocal() as session:
                pending = session.query(Analysis).filter(Analysis.status == 'pending').order_by(Analysis.id).with_for_update().first()
                if not pending:
                    await asyncio.sleep(WORKER_POLL_SECONDS)
                    continue

                pending.status = "in_progress"
                pending.analyzed_at = None
                session.add(pending)
                session.commit()
                analysis_id = pending.id
                file_id = pending.file_id
                logger.info(f"Claimed analysis {analysis_id} for file {file_id}")

            try:
                await asyncio.to_thread(_run_analysis_sync, analysis_id, file_id)
                logger.info(f"Analysis {analysis_id} finished successfully.")
            except Exception as e:
                logger.exception(f"Error processing analysis {analysis_id}: {e}")
                with SessionLocal() as session:
                    a = session.query(Analysis).filter(Analysis.id == analysis_id).first()
                    if a:
                        a.status = "failed"
                        session.add(a)
                        session.commit()
        except asyncio.CancelledError:
            logger.info("Worker loop cancelled; exiting.")
            break
        except Exception:
            logger.exception("Unexpected error in worker loop.")
            await asyncio.sleep(2.0)


def _run_analysis_sync(analysis_id: str, file_id: str):
    try:
        with SessionLocal() as session:
            file_obj = session.query(File).filter(File.id == file_id).first()
            if not file_obj:
                logger.error(f"File {file_id} not found for analysis {analysis_id}. Marking failed.")
                a = session.query(Analysis).filter(Analysis.id == analysis_id).first()
                if a:
                    a.status = "failed"
                    session.add(a)
                    session.commit()
                return

            import services.analysis as analysis_service
            analysis_service.analyze_file(session, file_obj, analysis_id=analysis_id)
    except Exception:
        logger.exception(f"Exception in _run_analysis_sync for analysis {analysis_id}: {traceback.format_exc()}")
        try:
            with SessionLocal() as session:
                a = session.query(Analysis).filter(Analysis.id == analysis_id).first()
                if a:
                    a.status = "failed"
                    session.add(a)
                    session.commit()
        except Exception:
            logger.exception("Failed to mark analysis as failed in DB.")
