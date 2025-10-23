import logging
import os
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine, exc as sqlalchemy_exc
from db.models import File, Analysis
# Importa a lógica principal de análise e as funções de emergência
from services.analysis import analyze_file, _mark_analysis_status_in_new_session, _save_error_alert_in_new_session

logger = logging.getLogger("sharpshark.task_runner")

def run_analysis_task(analysis_id: str, file_id: str):
    """
    Esta é a função 'entry point' que é executada no Process Pool Executor.
    Ela roda em um PROCESSO SEPARADO da API principal.
    
    Por isso, ela precisa criar sua própria conexão/sessão com o banco de dados.
    """
    logger.info(f"Task Runner: Análise {analysis_id} (Arquivo {file_id}) iniciada no processo {os.getpid()}.")

    # 1. Cria uma nova conexão/sessão de DB exclusiva para este processo
    try:
        db_engine = create_engine("sqlite:///./db/database.db")
        SessionLocalTask = sessionmaker(bind=db_engine, expire_on_commit=False, autoflush=False)
        session: Session = SessionLocalTask()
    except Exception as e:
        # Se nem conseguir conectar ao DB, usa a função de emergência (que cria sua própria conexão)
        logger.exception(f"Task Runner: Análise {analysis_id}: Falha CRÍTICA ao criar engine/session DB: {e}")
        _mark_analysis_status_in_new_session(analysis_id, "failed")
        _save_error_alert_in_new_session(analysis_id, f"Erro DB init Task: {str(e)[:1980]}")
        return

    try:
        # 2. Busca a Análise e atualiza seu status para 'in_progress'
        analysis_obj = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis_obj:
            logger.error(f"Task Runner: Análise {analysis_id} não encontrada no DB. Abortando tarefa.")
            return
        
        # Garante que o status seja 'pending' antes de mudar
        if analysis_obj.status == "pending":
            try:
                analysis_obj.status = "in_progress"
                session.commit()
                logger.info(f"Task Runner: Análise {analysis_id}: Status atualizado para 'in_progress'.")
            except sqlalchemy_exc.SQLAlchemyError as e:
                # Se falhar ao atualizar o status, aborta
                logger.error(f"Task Runner: Análise {analysis_id}: Falha DB ao atualizar status para 'in_progress': {e}. Abortando.")
                session.rollback()
                _mark_analysis_status_in_new_session(analysis_id, "failed")
                _save_error_alert_in_new_session(analysis_id, f"Erro DB set in_progress: {str(e)[:1970]}")
                return
        elif analysis_obj.status != "in_progress":
             logger.warning(f"Task Runner: Análise {analysis_id}: Status era '{analysis_obj.status}' ao invés de 'pending'. Continuando mesmo assim...")

        # 3. Busca o objeto File associado
        file_obj = session.query(File).filter(File.id == file_id).first()
        if not file_obj:
            # Se o arquivo não for encontrado (erro grave), marca a análise como falha
            logger.error(f"Task Runner: Análise {analysis_id}: Ficheiro associado {file_id} não encontrado. Marcando como falha.")
            try:
                analysis_obj.status = "failed"
                session.commit()
            except sqlalchemy_exc.SQLAlchemyError as e_fail:
                 logger.error(f"Task Runner: Análise {analysis_id}: Falha DB ao marcar como 'failed' (ficheiro não encontrado): {e_fail}")
                 session.rollback()
                 _mark_analysis_status_in_new_session(analysis_id, "failed")
            _save_error_alert_in_new_session(analysis_id, f"Ficheiro {file_id} não encontrado no DB")
            return

        # 4. Chama a função principal de análise (o trabalho pesado)
        analyze_file(session, file_obj, analysis_id=analysis_id)

        logger.info(f"Task Runner: Análise {analysis_id} concluída com sucesso (retorno de analyze_file).")

    except Exception as e:
        # Captura qualquer erro não tratado vindo de 'analyze_file'
        logger.exception(f"Task Runner: Erro CRÍTICO não tratado na análise {analysis_id} (Arquivo {file_id}): {e}")
        # Usa as funções de emergência para marcar como 'failed'
        _mark_analysis_status_in_new_session(analysis_id, "failed")
        _save_error_alert_in_new_session(analysis_id, f"Erro Task Runner: {str(e)[:1980]}")
    finally:
        # Garante que a sessão deste processo seja fechada
        logger.debug(f"Task Runner: Análise {analysis_id}: Fechando sessão DB.")
        session.close()
        logger.info(f"Task Runner: Análise {analysis_id} (Arquivo {file_id}) finalizada no processo {os.getpid()}.")