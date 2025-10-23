from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from db.models import Setting, User
from services.users import get_user_by_id
from api.schemas.settingsSchema import SettingsResponse
from core.config import INGEST_BASE_DIRECTORY
import os
import re
from typing import List, Optional

INGEST_FOLDER_KEY = "INGEST_FOLDER"
INGEST_USER_ID_KEY = "INGEST_USER_ID"
INGEST_PROJECT_NAME_KEY = "INGEST_PROJECT_NAME"

def get_current_settings(session: Session) -> SettingsResponse:
    folder = get_setting(session, INGEST_FOLDER_KEY)
    project_name = get_setting(session, INGEST_PROJECT_NAME_KEY)
    user_id = get_setting(session, INGEST_USER_ID_KEY)
    user_name = None

    if user_id:
        try:
            user = get_user_by_id(session, user_id)
            if user:
                user_name = user.name
        except HTTPException as e:
            if e.status_code == 404:
                user_name = None
            else:
                pass

    return SettingsResponse(
        ingest_project_name=project_name,
        ingest_folder=folder,
        ingest_user_id=user_id,
        ingest_user_name=user_name
    )
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

def update_ingest_settings(session: Session, project_name_input: str, current_user_id: str) -> SettingsResponse:
    project_name = project_name_input.strip() if project_name_input else ""
    folder_path_to_save = ""
    user_id_to_save = ""
    project_name_to_save = ""

    if project_name:
        safe_name = re.sub(r'[^\w\-.]', '_', project_name)
        if not safe_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nome do projeto inválido após sanitização."
            )

        full_path = os.path.join(INGEST_BASE_DIRECTORY, safe_name)

        try:
            os.makedirs(full_path, exist_ok=True)
            if not os.path.isdir(full_path):
                 raise OSError(f"Caminho existe mas não é um diretório: {full_path}")
        except OSError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Não foi possível criar ou acessar o diretório de ingestão no servidor: {e}"
            )

        folder_path_to_save = full_path
        project_name_to_save = safe_name
        user_id_to_save = current_user_id
    else:
        pass

    try:
        set_setting(session, INGEST_FOLDER_KEY, folder_path_to_save)
        set_setting(session, INGEST_USER_ID_KEY, user_id_to_save)
        set_setting(session, INGEST_PROJECT_NAME_KEY, project_name_to_save)
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao salvar configurações no banco de dados: {e}"
        )
    return get_current_settings(session)