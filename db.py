from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from decouple import config

SQLALCHEMY_DATABASE_URL = f"postgresql://{config('name')}:{config('password')}@{config('host')}:{config('port')}/{config('database')}"  # "postgresql://tisdortkznjbvn:7a006df58e650010ebc441e5008dc120656ddc7932c31a1e924c462c42ac4035@ec2-176-34-215-248.eu-west-1.compute.amazonaws.com:5432/do9ntdr7diind"

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
