from fastapi import APIRouter, Depends, UploadFile, status, HTTPException, Request
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlalchemy import paginate
from sqlalchemy.orm import Session
from db.models import User
from api.schemas.fileSchema import FileRead
# 'require_active_user' é uma dependência que combina 'check_token' e 'is_active'
from api.schemas.dependencies import get_session, require_active_user 
import services.files as file_service

# Define o roteador para a seção de Arquivos (Uploads)
files_router = APIRouter(prefix="/files", tags=["files"])

@files_router.post("/upload", response_model=FileRead, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile, # O arquivo enviado via multipart/form-data
    request: Request, # Usado pelo rate limiter de upload
    current_user: User = Depends(require_active_user), # Requer usuário logado e ativo
    session: Session = Depends(get_session)
):
    """
    Endpoint para fazer upload de um novo arquivo .pcap/.pcapng.
    A lógica de validação, cálculo de hash e salvamento está no 'file_service'.
    """
    return await file_service.create_file(session, file, current_user.id, request)

@files_router.get("/", response_model=Page[FileRead])
def get_all_files(
    current_user: User = Depends(require_active_user),
    session: Session = Depends(get_session)
):
    """
    Lista todos os arquivos no sistema (com paginação).
    (Nota: Este endpoint pode precisar de filtro de permissão,
    atualmente lista tudo para qualquer usuário ativo)
    """
    query = file_service.get_files_query(session)
    return paginate(query)

@files_router.get("/{file_id}", response_model=FileRead)
def get_file(
    file_id: str, 
    current_user: User = Depends(require_active_user), 
    session: Session = Depends(get_session)
):
    """
    Obtém informações de um arquivo específico pelo ID.
    (Nota: Também pode precisar de filtro de permissão)
    """
    file = file_service.get_file_by_id(session, file_id)
    return file

@files_router.get("/hash/{file_hash}", response_model=FileRead)
def get_file_by_hash(
    file_hash: str, 
    current_user: User = Depends(require_active_user), 
    session: Session = Depends(get_session)
):
    """
    Obtém informações de um arquivo pelo seu hash SHA256.
    """
    file = file_service.get_file_by_hash(session, file_hash)
    return file

@files_router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    file_id: str, 
    current_user: User = Depends(require_active_user), 
    session: Session = Depends(get_session)
):
    """
    Deleta um arquivo.
    Apenas o dono do arquivo ou um superusuário pode deletar.
    """
    file = file_service.get_file_by_id(session, file_id)
    # Verificação de permissão para deleção
    if file.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Sem permissão para deletar este ficheiro")
    
    file_service.delete_file(session, file_id)
    return None