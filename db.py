from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from decouple import config
from settings import Settings

settings = Settings()
SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.database_name}:{settings.database_password}@{settings.database_host}:{settings.database_port}/{settings.database}"
# SQLALCHEMY_DATABASE_URL = f"postgresql://{config('name')}:{config('password')}@{config('host')}:{config('port')}/{config('database')}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
