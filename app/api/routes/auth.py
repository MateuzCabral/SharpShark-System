from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session
from api.schemas.userSchema import LoginSchema
import services.auth as auth_service

auth_router = APIRouter(prefix="/auth", tags=["auth"])

@auth_router.post("/login", status_code=status.HTTP_200_OK)
def login(login: LoginSchema, session: Session = Depends(get_session)):
    user = auth_service.verify_user_credentials(login.name, login.password, session)
    return auth_service.generate_access_token(user)

@auth_router.post("/login-form", status_code=status.HTTP_200_OK)
def login_form(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = auth_service.verify_user_credentials(form.username, form.password, session)
    return auth_service.generate_access_token(user)