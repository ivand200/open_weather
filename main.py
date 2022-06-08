from fastapi import FastAPI

from routers.users import router as router_users

app = FastAPI()


app.include_router(
    router_users,
    prefix="/api/v1",
    tags=["users"]
)
