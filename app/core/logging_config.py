import logging
import os
from logging.handlers import RotatingFileHandler

# Nome padrão para o logger da aplicação
APP_LOGGER_NAME = "sharpshark"

def setup_logging():
    """ Configura o sistema de logging da aplicação. """
    log_dir = "logs"
    log_filename = os.path.join(log_dir, "sharpshark.log")

    # Cria o diretório de logs se ele não existir
    os.makedirs(log_dir, exist_ok=True)

    # Formato padrão para as mensagens de log
    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )

    # --- Handler para Arquivo (com Rotação) ---
    # 'RotatingFileHandler' evita que o arquivo de log cresça indefinidamente
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=10*1024*1024, # 10 MB por arquivo
        backupCount=5, # Mantém 5 arquivos de backup (ex: sharpshark.log.1, ...log.5)
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO) # Nível de log para o arquivo

    # --- Handler para Console ---
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO) # Nível de log para o console

    # --- Configura o Logger Principal da Aplicação ---
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    app_logger.setLevel(logging.INFO)

    # Adiciona os handlers (arquivo e console) ao logger
    if not app_logger.handlers:
        app_logger.addHandler(file_handler)
        app_logger.addHandler(console_handler)

    # Impede que o log seja propagado para o logger 'root' (evita duplicidade)
    app_logger.propagate = False

    # --- Configura o Logger de Acesso do Uvicorn ---
    # Captura os logs de acesso (ex: "GET /users 200 OK")
    uvicorn_logger = logging.getLogger("uvicorn.access")
    if not uvicorn_logger.handlers:
        # Direciona os logs de acesso também para o arquivo
        uvicorn_logger.addHandler(file_handler) 
    uvicorn_logger.propagate = False