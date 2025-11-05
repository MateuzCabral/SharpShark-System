import logging
import os
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from fastapi import HTTPException, status
from db.models import Setting, User
from services.users import get_user_by_id
from api.schemas.settingsSchema import SettingsResponse
from typing import List, Optional
from core.config import INGEST_BASE_DIRECTORY 

logger = logging.getLogger("sharpshark.settings")

INGEST_FOLDER_KEY = "INGEST_FOLDER"
INGEST_USER_ID_KEY = "INGEST_USER_ID"
INGEST_PROJECT_NAME_KEY = "INGEST_PROJECT_NAME"

def _is_safe_path_component(component: str) -> bool:
    if not component:
        return False
    normalized = os.path.normpath(component)
    if os.path.isabs(normalized):
        return False
    if ".." in normalized.split(os.sep):
        return False
    if os.path.dirname(normalized) and os.path.dirname(normalized) != '':
        return False
    if normalized == "." or normalized == "":
        return False
    return True

def get_current_settings(session: Session) -> SettingsResponse:
    logger.debug("Buscando configurações atuais de ingestão...")
    try:
        folder = get_setting(session, INGEST_FOLDER_KEY)
        project_name = get_setting(session, INGEST_PROJECT_NAME_KEY)
        user_id = get_setting(session, INGEST_USER_ID_KEY)
        user_name = None

        if user_id:
            try:
                user = get_user_by_id(session, user_id)
                if user: user_name = user.name
            except HTTPException as e:
                if e.status_code == 404:
                    logger.warning(f"Usuário de ingestão (ID: {user_id}) não encontrado no DB. Retornando nome nulo.")
                    user_name = None
                else:
                    logger.error(f"Erro inesperado ao buscar usuário de ingestão {user_id}: {e.detail}")
            except Exception as e_user:
                logger.exception(f"Erro GERAL ao buscar usuário de ingestão {user_id}: {e_user}")

        response = SettingsResponse(
            ingest_project_name=project_name, 
            ingest_folder=folder,
            ingest_user_id=user_id, 
            ingest_user_name=user_name
        )
        logger.debug(f"Configurações encontradas: {response.model_dump()}")
        return response
    except sqlalchemy_exc.SQLAlchemyError as e:
        logger.error(f"Erro DB ao buscar configurações de ingestão: {e}")
        raise HTTPException(status_code=500, detail="Erro ao buscar configurações do banco de dados.")
    except Exception as e:
        logger.exception(f"Erro inesperado em get_current_settings: {e}")
        raise HTTPException(status_code=500, detail="Erro interno inesperado ao buscar configurações.")

def get_setting(session: Session, key: str) -> Optional[str]:
    setting = session.query(Setting).filter(Setting.key == key).first()
    return setting.value if setting else None

def set_setting(session: Session, key: str, value: Optional[str]) -> Setting:
    setting = session.query(Setting).filter(Setting.key == key).first()
    if setting:
        setting.value = value
    else:
        setting = Setting(key=key, value=value)
        session.add(setting)
    return setting

def get_all_settings(session: Session) -> List[Setting]:
    return session.query(Setting).all()

def update_ingest_settings(session: Session, ingest_folder_input: Optional[str], current_user_id: str) -> SettingsResponse:
    project_name = ingest_folder_input.strip() if ingest_folder_input else ""
    logger.info(f"Admin {current_user_id}: Atualizando configurações de ingestão. Projeto: '{project_name}'")

    project_name_to_save = ""

    if project_name:
        if not _is_safe_path_component(project_name):
            logger.warning(f"Admin {current_user_id}: Nome de projeto rejeitado. Contém caracteres inválidos (.. / \): '{project_name}'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nome do projeto inválido. Use apenas um nome simples, sem barras (/) ou (..)."
            )

        full_path_to_check = os.path.join(INGEST_BASE_DIRECTORY, project_name)
        
        try:
            if not os.path.exists(full_path_to_check):
                logger.info(f"Admin {current_user_id}: Pasta '{full_path_to_check}' não existe. Criando...")
                os.makedirs(full_path_to_check, exist_ok=True)
                logger.info(f"Pasta '{full_path_to_check}' criada com sucesso no container (e no host).")

            if not os.path.isdir(full_path_to_check):
                raise HTTPException(status_code=400, detail="O caminho é um arquivo, não uma pasta.")
            if not os.access(full_path_to_check, os.R_OK) or not os.access(full_path_to_check, os.W_OK):
                raise HTTPException(status_code=403, detail="Permissão negada. O servidor não pode ler/escrever nessa pasta.")
                
        except OSError as e:
            logger.error(f"Admin {current_user_id}: Erro OSError ao validar/criar o caminho {full_path_to_check}: {e}")
            raise HTTPException(status_code=500, detail=f"Erro no servidor ao tentar acessar ou criar o caminho: {e}")
        
        logger.info(f"Admin {current_user_id}: Caminho de ingestão validado com sucesso: {full_path_to_check}")
        project_name_to_save = project_name

    else:
        logger.info(f"Admin {current_user_id}: Limpando configurações de ingestão (projeto vazio).")

    try:
        set_setting(session, INGEST_FOLDER_KEY, project_name_to_save)
        set_setting(session, INGEST_PROJECT_NAME_KEY, project_name_to_save) 
        set_setting(session, INGEST_USER_ID_KEY, current_user_id)
        
        session.commit()
        logger.info(f"Admin {current_user_id}: Configurações de ingestão salvas no DB com sucesso.")
    except sqlalchemy_exc.SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Admin {current_user_id}: Erro DB ao salvar configurações de ingestão: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao salvar configurações no banco de dados: {e}"
        )
    except Exception as e:
        session.rollback()
        logger.exception(f"Admin {current_user_id}: Erro inesperado ao salvar configurações: {e}")
        raise HTTPException(status_code=500, detail="Erro interno inesperado ao salvar configurações.")

    return get_current_settings(session)