# app/main.py
from fastapi import FastAPI
from api.routes.auth import auth_router
from api.routes.users import users_router
from api.routes.files import files_router
from api.routes.analyses import analyses_router
from api.routes.reports import reports_router
from api.routes.alerts import alert_router
from api.routes.stats import stats_router
from fastapi_pagination import add_pagination
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SharpShark API")

origins = ["*"]

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(files_router)
app.include_router(analyses_router)
app.include_router(alert_router)
app.include_router(stats_router)
app.include_router(reports_router)

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
    try:
        from services import worker
        await worker.launch_background_worker(app)
    except Exception as e:
        import logging
        logging.getLogger("sharpshark").exception(f"Failed to start worker: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    try:
        from services import worker
        await worker.stop_background_worker(app)
    except Exception:
        import logging
        logging.getLogger("sharpshark").exception("Failed to stop worker cleanly.")
