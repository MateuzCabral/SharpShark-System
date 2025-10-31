from pydantic import BaseModel
from typing import Optional

class SettingUpdate(BaseModel):
    ingest_folder: Optional[str] = None 

class SettingsResponse(BaseModel):
    ingest_project_name: Optional[str] = None
    ingest_folder: Optional[str] = None
    ingest_user_id: Optional[str] = None
    ingest_user_name: Optional[str] = None 

    class Config:
        from_attributes = True