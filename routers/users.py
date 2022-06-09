import time
import logging
import sys

from fastapi import APIRouter, Body, status, Depends, HTTPException, Header, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
from typing import Optional
from decouple import config

from schemas.users import UserCreate, UserPublic, ItemCreate, ItemPublic, UserItems
from models.users import User, Item
from routers.auth import signJWT, decodeJWT, transferJWT
from db import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler =logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


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
    logger.info("Check")
    return "Hello"


@router.post("/registration", status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create new user
    login: str
    password: str
    """
    logger.info(f"Registration a user with login: {user.login}")
    user_db = db.query(User).filter(User.login == user.login).first()
    if user_db:
        raise HTTPException(status_code=400, detail="login already exist.")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(login=user.login, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return signJWT(new_user.login)


@router.post("/login", status_code=status.HTTP_200_OK)
async def user_login(user: UserCreate, db: Session = Depends(get_db)):
    """
    User login
    """
    logging.info(f"Login user: {user.login}")
    if check_user(user, db):
        return signJWT(user.login)
    raise HTTPException(status_code=403, detail="Unauthorized")


# @router.delete("/users/{id}", status_code=status.HTTP_204_NO_CONTENT)
# async def user_delete(
#     id: int, db: Session = Depends(get_db), Authorization: Optional[str] = Header(None)
# ):
#     """
#     delete User by id
#     """


@router.post(
    "/items/new", response_model=ItemPublic, status_code=status.HTTP_201_CREATED
)
async def create_item(
    item: ItemCreate,
    db: Session = Depends(get_db),
    Authorization: Optional[str] = Header(None),
):
    """
    Create Item
    """
    logging.info(f"Create a item: {item}")
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    new_item = Item(title=item.title, user_id=item.user_id)
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item


@router.delete("/items/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(
    id: int,
    db: Session = Depends(get_db),
    Authorization: Optional[str] = Header(None),
):
    """
    Delete users item by id
    """
    logger.info(f"Delete item: {id}")
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    item = db.query(Item).filter(Item.id == id).first()
    user = db.query(User).filter(User.login == token["user_id"]).first()
    if item.user_id != user.id:
        raise HTTPException(status_code=400, detail=f"Cant find item id: {id}")
    logger.info(f"Delete item with item.user_id: {item.user_id}, user.id: {user.id}")
    db.delete(item)
    db.commit()
    return "ok"


@router.get("/items", response_model=UserItems, status_code=status.HTTP_200_OK)
async def get_items(
    db: Session = Depends(get_db),
    Authorization: Optional[str] = Header(None),
):
    """
    Get all user items
    """
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    user = db.query(User).filter(User.login == token["user_id"]).first()
    items = db.query(Item).filter(Item.user_id == user.id).all()
    logging.info(f"Get all items, user: {user.login}, items: {len(items)}")
    result = UserItems(user=user, items=items)
    return result


@router.post("/send", status_code=status.HTTP_201_CREATED)
async def link_item(
    user_login: str = Body(...),
    item_id: int = Body(...),
    db: Session = Depends(get_db),
    Authorization: Optional[str] = Header(None),
):
    """
    Item transfer to other user
    """
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    user = db.query(User).filter(User.login == token["user_id"]).first()
    item = db.query(Item).filter(Item.id == item_id).first()
    if item.user_id != user.id:
        raise HTTPException(status_code=400, detail=f"Cant find item id: {id}")
    logging.info(f"Send item transfer from user: {user.login}, item: {item.id}")
    user_login_jwt = transferJWT(user_login)
    user_token = user_login_jwt.decode("utf-8")
    url = f"{config('backend_url')}/{user_token}/{item_id}"
    return url


@router.get("/{user_token}/{item_id}", status_code=status.HTTP_200_OK)
async def get_transfer(
    user_token: str,
    item_id: int,
    db: Session = Depends(get_db),
    Authorization: Optional[str] = Header(None),
):
    """
    Get item transfer
    """
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    logging.info(f"Get item transfer, item: {item_id}, user: {token['user_id']}")
    user = db.query(User).filter(User.login == token["user_id"]).first()
    check_user_token = decodeJWT(user_token)
    if not check_user or check_user_token["user_id"] != user.login:
        raise HTTPException(status_code=400, detail="Something wrong!")
    item = db.query(Item).filter(Item.id == item_id).first()
    item.user_id = user.id
    db.commit()
    return "ok"
