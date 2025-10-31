from fastapi import FastAPI
from api.routes.auth import auth_router
from api.routes.users import users_router
from api.routes.files import files_router
from api.routes.analyses import analyses_router
from api.routes.alerts import alert_router
from api.routes.stats import stats_router
from api.routes.settings import settings_router
from api.routes.custom_rules import custom_rules_router
from fastapi_pagination import add_pagination
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from core.logging_config import setup_logging, APP_LOGGER_NAME
from db.models import Base, db

setup_logging()
app_logger = logging.getLogger(APP_LOGGER_NAME)

Base.metadata.create_all(bind=db)

app = FastAPI(title="SharpShark API")

origins = ["*"]

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(files_router)
app.include_router(analyses_router)
app.include_router(alert_router)
app.include_router(stats_router)
app.include_router(settings_router)
app.include_router(custom_rules_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

add_pagination(app)

@app.on_event("startup")
async def startup_event():
    cpu_cores = os.cpu_count() or 1
    app.state.process_pool = ProcessPoolExecutor(max_workers=cpu_cores)
    app_logger.info(f"Process Pool iniciado com {cpu_cores} workers.")

    try:
        from services import ingestor
        await ingestor.launch_background_ingestor(app)
    except Exception as e:
        app_logger.exception(f"Falha ao iniciar o ingestor: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    app_logger.info("A encerrar o Process Pool...")
    app.state.process_pool.shutdown(wait=True)
    app_logger.info("Process Pool encerrado.")

    try:
        from services import ingestor
        await ingestor.stop_background_ingestor(app)
    except Exception:
        app_logger.exception("Falha ao parar o ingestor de forma limpa.")