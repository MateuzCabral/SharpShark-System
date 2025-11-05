import typer
import logging
from sqlalchemy.orm import sessionmaker
from db.models import db, User, Base
from core.security import argon_context
from api.schemas.dependencies import get_session
import os

app = typer.Typer()
logger = logging.getLogger("sharpshark.cli")

SessionLocal = sessionmaker(bind=db, expire_on_commit=False)

def get_cli_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@app.command()
def create_admin():
    print("--- Criando Novo Administrador SharpShark ---")
    
    name = typer.prompt("Nome do usuário")
    password = typer.prompt("Senha (mínimo 8 caracteres)", hide_input=True, confirmation_prompt=True)
    
    if len(password) < 8:
        typer.secho("Erro: A senha deve ter no mínimo 8 caracteres.", fg=typer.colors.RED)
        raise typer.Abort()

    session = next(get_cli_session())
    
    try:
        existing = session.query(User).filter(User.name == name).first()
        if existing:
            typer.secho(f"Erro: Usuário '{name}' já existe.", fg=typer.colors.RED)
            raise typer.Abort()

        hashed_password = argon_context.hash(password)

        new_admin = User(
            name=name,
            password=hashed_password,
            is_active=True,
            is_superuser=True
        )
        
        session.add(new_admin)
        session.commit()
        
        typer.secho(f"Sucesso! Administrador '{name}' criado.", fg=typer.colors.GREEN)

    except Exception as e:
        session.rollback()
        typer.secho(f"Erro inesperado ao criar admin: {e}", fg=typer.colors.RED)
    finally:
        session.close()

@app.command()
def init_db():
    try:
        print("Inicializando banco de dados...")
        Base.metadata.create_all(bind=db)
        print("Tabelas do banco de dados verificadas/criadas com sucesso.")
    except Exception as e:
        typer.secho(f"Erro ao inicializar o banco de dados: {e}", fg=typer.colors.RED)
        raise typer.Abort()


if __name__ == "__main__":
    db_path_str = str(db.url).replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path_str)
    if not os.path.exists(db_dir):
        print(f"Criando diretório do banco de dados em: {db_dir}")
        os.makedirs(db_dir, exist_ok=True)
        
    app()