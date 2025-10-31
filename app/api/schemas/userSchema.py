from pydantic import BaseModel, Field
from typing import Optional

class UserCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=150)
    password: str = Field(..., min_length=8, max_length=64)
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False

    class Config:
        from_attributes = True

class UserRead(BaseModel):
    id: str
    name: str
    is_active: bool
    is_superuser: bool

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=150)
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False

    class Config:
        from_attributes = True

class LoginSchema(BaseModel):
    name: str
    password: str
    class Config:
        from_attributes = True