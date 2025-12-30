from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from typing import Optional

class User(BaseModel):
    id: Optional[str] = None
    email: EmailStr
    username: Optional[str] = None
    password_hash: str
    is_verified: bool = False
    is_active: bool = True
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(
        validate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={datetime: lambda v: v.isoformat()}
    )

        