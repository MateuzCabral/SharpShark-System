import logging
import os
import re
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from fastapi import HTTPException, status
from db.models import Setting, User
from services.users import get_user_by_id
from api.schemas.settingsSchema import SettingsResponse
from core.config import INGEST_BASE_DIRECTORY
from typing import List, Optional

logger = logging.getLogger("sharpshark.settings")

INGEST_FOLDER_KEY = "INGEST_FOLDER"
INGEST_USER_ID_KEY = "INGEST_USER_ID"
INGEST_PROJECT_NAME_KEY = "INGEST_PROJECT_NAME"

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
            ingest_project_name=project_name, ingest_folder=folder,
            ingest_user_id=user_id, ingest_user_name=user_name
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

def update_ingest_settings(session: Session, project_name_input: Optional[str], current_user_id: str) -> SettingsResponse:
    project_name = project_name_input.strip() if project_name_input else ""
    logger.info(f"Admin {current_user_id}: Atualizando configurações de ingestão. Nome do projeto: '{project_name}'")

    folder_path_to_save = ""
    user_id_to_save = ""
    project_name_to_save = ""

    if project_name:
        safe_name = re.sub(r'[^\w\-.]', '_', project_name)
        if not safe_name:
            logger.warning(f"Admin {current_user_id}: Nome de projeto inválido após sanitização: '{project_name}' -> '{safe_name}'")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nome do projeto inválido após sanitização.")

        full_path = os.path.join(INGEST_BASE_DIRECTORY, safe_name)
        logger.info(f"Admin {current_user_id}: Caminho de ingestão definido como: {full_path}")

        try:
            os.makedirs(full_path, exist_ok=True)
            if not os.path.isdir(full_path):
                 raise OSError(f"Caminho existe mas não é um diretório: {full_path}")
            logger.info(f"Admin {current_user_id}: Diretório de ingestão acessível/criado: {full_path}")
        except OSError as e:
            logger.error(f"Admin {current_user_id}: Falha OSError ao criar/acessar diretório {full_path}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Não foi possível criar ou acessar o diretório de ingestão no servidor: {e}"
            )
        
        folder_path_to_save = full_path
        project_name_to_save = safe_name
        user_id_to_save = current_user_id
    else:
        logger.info(f"Admin {current_user_id}: Limpando configurações de ingestão (projeto vazio).")

    try:
        set_setting(session, INGEST_FOLDER_KEY, folder_path_to_save)
        set_setting(session, INGEST_USER_ID_KEY, user_id_to_save)
        set_setting(session, INGEST_PROJECT_NAME_KEY, project_name_to_save)
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