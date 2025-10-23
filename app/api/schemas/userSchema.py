from pydantic import BaseModel, Field
from typing import Optional

class UserCreate(BaseModel):
    """ Schema para 'criar' um novo usuário (validação de campos). """
    name: str = Field(..., min_length=3, max_length=150)
    password: str = Field(..., min_length=8, max_length=64) # Valida tamanho mínimo da senha
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False

    class Config:
        from_attributes = True

class UserRead(BaseModel):
    """ Schema para 'ler' um usuário (nunca retorna a senha). """
    id: str
    name: str
    is_active: bool
    is_superuser: bool

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    """ Schema para 'atualizar' um usuário (todos os campos são opcionais). """
    name: Optional[str] = Field(None, min_length=3, max_length=150)
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False

    class Config:
        from_attributes = True

class LoginSchema(BaseModel):
    """ Schema para o endpoint de login /auth/login (JSON). """
    name: str
    password: str
    class Config:
        from_attributes = True