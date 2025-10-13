from fastapi import FastAPI
from api.routes.auth import auth_router
from api.routes.users import users_router
from api.routes.files import files_router
from fastapi_pagination import add_pagination

app = FastAPI(title="SharpShark API")

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(files_router)

add_pagination(app)
