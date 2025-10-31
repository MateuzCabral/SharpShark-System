import logging
import os
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from fastapi import HTTPException, status
from db.models import Setting, User
from services.users import get_user_by_id
from api.schemas.settingsSchema import SettingsResponse
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
    folder_path = ingest_folder_input.strip() if ingest_folder_input else ""
    logger.info(f"Admin {current_user_id}: Atualizando configurações de ingestão. Caminho: '{folder_path}'")

    folder_path_to_save = ""
    user_id_to_save = ""
    project_name_to_save = ""

    if folder_path:
        if not os.path.isabs(folder_path):
            logger.warning(f"Admin {current_user_id}: Caminho de ingestão rejeitado. Não é um caminho absoluto: '{folder_path}'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Caminho inválido. O caminho da pasta deve ser absoluto (ex: /mnt/capturas/ ou C:\\Users\\...)."
            )

        try:
            if not os.path.exists(folder_path):
                logger.warning(f"Admin {current_user_id}: Caminho de ingestão rejeitado. O caminho não existe: '{folder_path}'")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Caminho não encontrado no servidor: '{folder_path}'. Verifique o caminho ou crie o diretório."
                )
            if not os.path.isdir(folder_path):
                logger.warning(f"Admin {current_user_id}: Caminho de ingestão rejeitado. O caminho é um arquivo, não um diretório: '{folder_path}'")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Caminho inválido. O caminho fornecido é um arquivo, não uma pasta: '{folder_path}'."
                )
            if not os.access(folder_path, os.R_OK):
                 logger.error(f"Admin {current_user_id}: Permissão negada. O servidor não pode ler o diretório: '{folder_path}'")
                 raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permissão negada. O servidor não pode ler o diretório: '{folder_path}'."
                )
        except OSError as e:
            logger.error(f"Admin {current_user_id}: Erro OSError ao validar o caminho {folder_path}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro no servidor ao tentar acessar o caminho: {e}"
            )
        
        logger.info(f"Admin {current_user_id}: Caminho de ingestão validado com sucesso: {folder_path}")
        folder_path_to_save = folder_path
        user_id_to_save = current_user_id

    else:
        logger.info(f"Admin {current_user_id}: Limpando configurações de ingestão (caminho vazio).")

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