from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.dependencies import get_session, check_token, require_superuser
import services.settings as settings_service
from api.schemas.settingsSchema import SettingUpdate, SettingsResponse

# Define o roteador para a seção de Configurações
settings_router = APIRouter(prefix="/settings", tags=["Settings"])

@settings_router.put("/", response_model=SettingsResponse)
def update_settings_endpoint(
    settings_data: SettingUpdate, # Dados a serem atualizados
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Atualiza as configurações do sistema. Apenas superusuários.
    Especificamente, atualiza as configurações de "ingestão" (ingest).
    """
    require_superuser(current_user)
    return settings_service.update_ingest_settings(
        session=session,
        project_name_input=settings_data.ingest_project_name,
        current_user_id=current_user.id
    )

@settings_router.get("/", response_model=SettingsResponse)
def get_settings_endpoint(
    current_user: User = Depends(check_token),
    session: Session = Depends(get_session)
):
    """
    Obtém as configurações atuais do sistema. Apenas superusuários.
    """
    require_superuser(current_user)
    return settings_service.get_current_settings(session=session)