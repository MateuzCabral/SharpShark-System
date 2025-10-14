from fastapi import FastAPI
from api.routes.auth import auth_router
from api.routes.users import users_router
from api.routes.files import files_router
from api.routes.analyses import analyses_router
from api.routes.reports import reports_router
from api.routes.alerts import alert_router
from api.routes.stats import stats_router
from fastapi_pagination import add_pagination

app = FastAPI(title="SharpShark API")

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(files_router)
app.include_router(analyses_router)
app.include_router(alert_router)
app.include_router(stats_router)
app.include_router(reports_router)

add_pagination(app)
