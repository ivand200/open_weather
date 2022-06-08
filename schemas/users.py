from typing import List, Optional

from pydantic import BaseModel, validator, Field


class UserBase(BaseModel):
    login: str


class UserCreate(UserBase):
    password: str


class UserPublic(UserBase):
    id: int

    class Config:
        orm_mode = True
