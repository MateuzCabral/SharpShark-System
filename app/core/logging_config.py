import logging
import os
from logging.handlers import RotatingFileHandler

APP_LOGGER_NAME = "sharpshark"

def setup_logging():
    log_dir = "logs"
    log_filename = os.path.join(log_dir, "sharpshark.log")

    os.makedirs(log_dir, exist_ok=True)

    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )

    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)

    app_logger = logging.getLogger(APP_LOGGER_NAME)
    app_logger.setLevel(logging.INFO)

    if not app_logger.handlers:
        app_logger.addHandler(file_handler)
        app_logger.addHandler(console_handler)

    app_logger.propagate = False

    uvicorn_logger = logging.getLogger("uvicorn.access")
    if not uvicorn_logger.handlers:
        uvicorn_logger.addHandler(file_handler) 
    uvicorn_logger.propagate = False