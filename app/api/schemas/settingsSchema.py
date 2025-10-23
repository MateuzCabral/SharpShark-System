from pydantic import BaseModel
from typing import Optional

class SettingUpdate(BaseModel):
    """ Schema para 'atualizar' configurações (entrada). """
    ingest_project_name: Optional[str] = None 

class SettingsResponse(BaseModel):
    """ Schema para 'ler' (retornar) as configurações atuais. """
    ingest_project_name: Optional[str] = None
    ingest_folder: Optional[str] = None
    ingest_user_id: Optional[str] = None
    ingest_user_name: Optional[str] = None 

    class Config:
        from_attributes = True