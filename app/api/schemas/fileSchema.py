from pydantic import BaseModel
from datetime import datetime


class FileBase(BaseModel):
    """ Schema base para Arquivo. """
    file_name: str
    file_size: float
    file_hash: str


class FileCreate(FileBase):
    """ Schema usado ao criar (usado internamente, upload usa 'UploadFile'). """
    pass


class FileRead(FileBase):
    """ Schema usado para 'ler' (retornar) dados de um Arquivo. """
    id: str
    file_path: str
    file_hash: str
    uploaded_at: datetime
    user_id: str

    class Config:
        from_attributes = True