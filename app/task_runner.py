import logging
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from db.models import File, Analysis
from services.analysis import analyze_file

logger = logging.getLogger("sharpshark.task_runner")

def run_analysis_task(analysis_id: str, file_id: str):
    logger.info(f"Processo de análise iniciado para a análise {analysis_id} (arquivo {file_id})")
    
    db_engine = create_engine("sqlite:///./db/database.db")
    SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False, autoflush=False)

    session = SessionLocal()
    try:
        analysis_obj = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if analysis_obj and analysis_obj.status == "pending":
            analysis_obj.status = "in_progress"
            session.commit()
            logger.info(f"Status da análise {analysis_id} atualizado para 'in_progress'.")
        elif not analysis_obj:
            logger.error(f"Análise {analysis_id} não encontrada na base de dados. A abortar a tarefa.")
            return
        
        file_obj = session.query(File).filter(File.id == file_id).first()
        if not file_obj:
            logger.error(f"Ficheiro {file_id} não encontrado. A marcar análise {analysis_id} como falha.")
            if analysis_obj:
                analysis_obj.status = "failed"
                session.commit()
            return

        analyze_file(session, file_obj, analysis_id=analysis_id)
        logger.info(f"Análise {analysis_id} concluída com sucesso.")

    except Exception as e:
        logger.exception(f"Erro crítico no processo de análise {analysis_id}: {e}")
        _mark_analysis_status_in_new_session(analysis_id, "failed")
    finally:
        session.close()

def _mark_analysis_status_in_new_session(analysis_id: str, status: str):
    db_engine = create_engine("sqlite:///./db/database.db")
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    try:
        analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if analysis:
            analysis.status = status
            session.commit()
    except Exception as db_e:
        logger.error(f"Falha ao atualizar o status da análise {analysis_id} para '{status}': {db_e}")
    finally:
        session.close()