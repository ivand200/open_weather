from pydantic import BaseSettings


class Settings(BaseSettings):
    database_name: str
    database_password: str
    database_host: str
    database_port: int
    database: str
    backend_url: str

    class Config:
        env_file = ".env"
