import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env (se existir)
load_dotenv()

# --- Configurações de Segurança (Rate Limiting) ---
# Lê do .env ou usa um valor padrão
LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", 5)) # 5 tentativas
LOGIN_RATE_PERIOD = int(os.getenv("LOGIN_RATE_PERIOD", 600)) # por 600 seg (10 min)

UPLOAD_RATE_LIMIT = int(os.getenv("UPLOAD_RATE_LIMIT", 10)) # 10 uploads
UPLOAD_RATE_PERIOD = int(os.getenv("UPLOAD_RATE_PERIOD", 3600)) # por 3600 seg (1 hora)

# --- Configurações de Diretórios ---
UPLOAD_DIRECTORY = os.getenv("UPLOAD_DIRECTORY", "./uploads")
INGEST_BASE_DIRECTORY = os.path.abspath(os.getenv("INGEST_BASE_DIRECTORY", "./uploads/ingest"))