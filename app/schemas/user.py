from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    username: Optional[str] = None
    is_active: Optional[bool] = None

class UserInDB(UserBase):
    id: str
    password_hash: str
    is_verified: bool = False
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

class UserResponse(UserBase):
    id: str
    is_verified: bool
    is_active: bool
    created_at: datetime