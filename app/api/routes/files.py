from fastapi import APIRouter, Depends, UploadFile, status, HTTPException
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.fileSchema import FileRead
from api.schemas.dependencies import get_session, require_active_user
import services.files as file_service

files_router = APIRouter(prefix="/files", tags=["files"])

@files_router.post("/upload", response_model=FileRead, status_code=status.HTTP_201_CREATED)
def upload_file(
    file: UploadFile,
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    return file_service.create_file(session, file, current_user.id)


@files_router.get("/", response_model=Page[FileRead])
def get_all_files(
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    query = file_service.get_files_query(session)
    if not current_user.is_superuser:
        query = query.filter(file_service.File.user_id == current_user.id)
    return paginate(query)


@files_router.get("/{file_id}", response_model=FileRead)
def get_file(file_id: str, current_user: User = Depends(require_active_user), session: Session = Depends(get_session)):
    file = file_service.get_file_by_id(session, file_id)
    if file.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Sem permissão para acessar este arquivo")
    return file

@files_router.get("/hash/{file_hash}", response_model=FileRead)
def get_file_by_hash(file_hash: str, current_user: User = Depends(require_active_user), session: Session = Depends(get_session)):
    file = file_service.get_file_by_hash(session, file_hash)
    if file.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Sem permissão para acessar este arquivo")
    return file

@files_router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(file_id: str, current_user: User = Depends(require_active_user), session: Session = Depends(get_session)):
    file = file_service.get_file_by_id(session, file_id)
    if file.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Sem permissão para deletar este arquivo")
    file_service.delete_file(session, file_id)
    return None