from fastapi import Depends, HTTPException, status, UploadFile
from sqlalchemy.orm import sessionmaker, Session
from db.models import db, User
from jose import jwt, JWTError
from core.security import SECRET_KEY, ALGORITHM, oauth2_schema
import hashlib

# Cria um 'fabricante' de sessões ligado ao engine do banco (db)
SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

def get_session():
    """
    Dependência do FastAPI para Injeção de Dependência da sessão do DB.
    Isso garante que cada request tenha sua própria sessão e que ela
    seja fechada ao final, mesmo se ocorrer um erro.
    """
    session = SessionLocal()
    try:
        yield session # Fornece a sessão para a rota
    finally:
        session.close() # Fecha a sessão ao final do request

def check_token(
    token: str = Depends(oauth2_schema), # Obtém o token "Bearer" do header Authorization
    session: Session = Depends(get_session)
) -> User:
    """
    Dependência de segurança principal.
    Valida o token JWT e retorna o objeto User correspondente.
    """
    try:
        # Decodifica o token usando a chave secreta e o algoritmo
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 'sub' (subject) é onde geralmente armazenamos o ID do usuário
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        user_id = str(sub)
    except JWTError:
        # Erro se o token for inválido, expirado ou malformado
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or expired")
    
    # Busca o usuário no banco de dados
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        # Caso o usuário tenha sido deletado após o token ser emitido
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user # Injeta o objeto User na rota

def require_superuser(user: User):
    """
    Função auxiliar (não é uma dependência direta, mas usada por elas)
    para verificar se um usuário é superusuário.
    """
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas superusers podem acessar este recurso"
        )

def require_active_user(current_user: User = Depends(check_token)) -> User:
    """
    Dependência que combina 'check_token' e uma verificação 'is_active'.
    Usada para endpoints que qualquer usuário logado E ativo pode acessar.
    """
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuário Inativo")
    return current_user


def calculate_file_hash(file: UploadFile) -> str:
    """
    Função utilitária para calcular o hash SHA256 de um arquivo (UploadFile).
    """
    sha256 = hashlib.sha256()
    file.file.seek(0) # Garante que o ponteiro do arquivo esteja no início
    # Lê o arquivo em 'chunks' (pedaços) para não sobrecarregar a memória
    while chunk := file.file.read(8192):
        sha256.update(chunk)
    file.file.seek(0) # Retorna o ponteiro ao início para uso futuro (ex: salvar)
    return sha256.hexdigest()

def validate_pcap_header(file: UploadFile):
    """
    Valida o 'magic number' (primeiros 4 bytes) do arquivo para
    garantir que é um formato pcap ou pcapng.
    """
    header = file.file.read(4) # Lê os primeiros 4 bytes
    file.file.seek(0) # Retorna o ponteiro ao início

    # Magic numbers para .pcap (little-endian e big-endian)
    if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:
        return "pcap"

    # Magic number para .pcapng
    if header == b'\x0a\x0d\x0d\x0a':
        return "pcapng"

    # Se não for nenhum dos anteriores, rejeita o arquivo
    raise HTTPException(
        status_code=400,
        detail="Arquivo inválido: o conteúdo não corresponde a um arquivo .pcap ou .pcapng"
    )