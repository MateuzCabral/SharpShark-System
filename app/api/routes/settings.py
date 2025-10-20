from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.dependencies import get_session, check_token, require_superuser
import services.settings as settings_service
from services.users import get_user_by_id
from pydantic import BaseModel
from typing import Optional
import os
import re

from core.config import INGEST_BASE_DIRECTORY

settings_router = APIRouter(prefix="/settings", tags=["Settings"])

class SettingUpdate(BaseModel):
    ingest_project_name: str

class SettingsResponse(BaseModel):
    ingest_project_name: Optional[str] = None
    ingest_folder: Optional[str] = None
    ingest_user_id: Optional[str] = None
    ingest_user_name: Optional[str] = None
    
    class Config:
        from_attributes = True
@settings_router.put("/", response_model=SettingsResponse)
def update_settings(
    settings_data: SettingUpdate,
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    
    project_name = settings_data.ingest_project_name.strip()
    
    folder_path_to_save = ""
    user_id_to_save = ""
    project_name_to_save = ""

    if project_name:
        safe_name = re.sub(r'[^\w\-]', '_', project_name)
        if not safe_name:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nome do projeto inválido."
            )
            
        full_path = os.path.join(INGEST_BASE_DIRECTORY, safe_name)
        
        try:
            os.makedirs(full_path, exist_ok=True)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Não foi possível criar o diretório no servidor: {e}"
            )
            
        folder_path_to_save = full_path
        project_name_to_save = safe_name
        user_id_to_save = current_user.id

    settings_service.set_setting(session, settings_service.INGEST_FOLDER_KEY, folder_path_to_save)
    settings_service.set_setting(session, settings_service.INGEST_USER_ID_KEY, user_id_to_save)
    settings_service.set_setting(session, settings_service.INGEST_PROJECT_NAME_KEY, project_name_to_save)
            
    return _get_current_settings(session)

@settings_router.get("/", response_model=SettingsResponse)
def get_settings(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    require_superuser(current_user)
    return _get_current_settings(session)

def _get_current_settings(session: Session) -> SettingsResponse:
    folder = settings_service.get_setting(session, settings_service.INGEST_FOLDER_KEY)
    project_name = settings_service.get_setting(session, settings_service.INGEST_PROJECT_NAME_KEY)
    user_id = settings_service.get_setting(session, settings_service.INGEST_USER_ID_KEY)
    user_name = None

    if user_id:
        try:
            user = get_user_by_id(session, user_id)
            if user:
                user_name = user.name
        except HTTPException:
            user_name = None 

    return SettingsResponse(
        ingest_project_name=project_name,
        ingest_folder=folder,
        ingest_user_id=user_id,
        ingest_user_name=user_name
    )