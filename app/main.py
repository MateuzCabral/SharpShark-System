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
from concurrent.futures import ProcessPoolExecutor # Para tarefas pesadas (CPU)
from core.logging_config import setup_logging, APP_LOGGER_NAME
from db.models import Base, db

# Configura o logging
setup_logging()
app_logger = logging.getLogger(APP_LOGGER_NAME)

# Cria as tabelas no banco de dados (se não existirem)
Base.metadata.create_all(bind=db)

# Inicializa a aplicação FastAPI
app = FastAPI(title="SharpShark API")

# Configuração do CORS (Cross-Origin Resource Sharing)
origins = ["*"] # Permite todas as origens (ajustar para produção)

# Inclui todos os roteadores
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(files_router)
app.include_router(analyses_router)
app.include_router(alert_router)
app.include_router(stats_router)
app.include_router(settings_router)
app.include_router(custom_rules_router)

# Adiciona o middleware do CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Adiciona o suporte à paginação (fastapi-pagination)
add_pagination(app)

@app.on_event("startup")
async def startup_event():
    """
    Funções executadas ao iniciar a API.
    """
    # 1. Inicializa o Process Pool Executor
    # Usado para rodar a análise de PCAP (CPU-bound) em processos separados,
    # não bloqueando a API.
    cpu_cores = os.cpu_count() or 1
    app.state.process_pool = ProcessPoolExecutor(max_workers=cpu_cores)
    app_logger.info(f"Process Pool iniciado com {cpu_cores} workers.")

    # 2. Inicia o serviço de Ingestão (Watchdog)
    try:
        from services import ingestor
        await ingestor.launch_background_ingestor(app)
    except Exception as e:
        app_logger.exception(f"Falha ao iniciar o ingestor: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Funções executadas ao encerrar a API.
    """
    # 1. Encerra o Process Pool
    app_logger.info("A encerrar o Process Pool...")
    # 'wait=True' garante que as análises em andamento terminem
    app.state.process_pool.shutdown(wait=True)
    app_logger.info("Process Pool encerrado.")

    # 2. Para o serviço de Ingestão (Watchdog)
    try:
        from services import ingestor
        await ingestor.stop_background_ingestor(app)
    except Exception:
        app_logger.exception("Falha ao parar o ingestor de forma limpa.")