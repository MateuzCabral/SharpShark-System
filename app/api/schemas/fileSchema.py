from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class FileBase(BaseModel):
    file_name: str
    file_size: float
    file_hash: str


class FileCreate(FileBase):
    pass

class FileReadSimple(BaseModel):
    file_name: str
    file_size: float
    file_hash: str

    class Config:
        from_attributes = True

class FileRead(FileBase):
    id: str
    file_path: str
    file_hash: str
    uploaded_at: datetime
    user_id: str

    class Config:
        from_attributes = True
