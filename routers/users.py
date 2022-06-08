import time

from fastapi import APIRouter, Body, status, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
from typing import Optional

from schemas.users import UserCreate, UserPublic
from models.users import User, Item
from routers.auth import signJWT
from db import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()


def check_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Check user in db
    """
    try:
        user_db = db.query(User).filter(User.login == user.login).first()
        varify_password = pwd_context.verify(user.password, user_db.password)
        if user_db and varify_password:
            return True
        return False
    except:
        False


@router.get("/test")
def test():
    return "Hello"


@router.post("/user/signup", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create new user
    login: str
    password: str
    """
    user_db = db.query(User).filter(User.login == user.login).first()
    if user_db:
        raise HTTPException(status_code=400, detail="login already exist.")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(login=user.login, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return signJWT(new_user.login)


@router.post("users/login", status_code=status.HTTP_200_OK)
async def user_login(user: UserCreate):
    """
    User login
    """
    if check_user(user):
        return signJWT(user.login)
    raise HTTPException(status_code=403, detail="Unauthorized")


@router.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def user_delete(id: int, db: Session = Depends(get_db), Authorization: Optional[str] = Header(None)):
    """
    delete User by id
    """
