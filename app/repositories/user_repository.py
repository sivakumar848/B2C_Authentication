from typing import Optional, List
from datetime import datetime
from bson import ObjectId
from app.core.database import db
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate

class UserRepository:
    
    @staticmethod
    async def create_user(user_data: UserCreate, password_hash: str) -> User:
        user_doc = {
            "email": user_data.email,
            "username": user_data.username,
            "password_hash": password_hash,
            "is_verified": False,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        result = await db.get_db().users.insert_one(user_doc)
        user_doc["id"] = str(result.inserted_id)
        return User(**user_doc)
    
    @staticmethod
    async def get_user_by_id(user_id: str) -> Optional[User]:
        user_doc = await db.get_db().users.find_one({"_id": ObjectId(user_id)})
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])
            return User(**user_doc)
        return None
    
    @staticmethod
    async def get_user_by_email(email: str) -> Optional[User]:
        user_doc = await db.get_db().users.find_one({"email": email})
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])
            return User(**user_doc)
        return None
    
    @staticmethod
    async def get_user_by_username(username: str) -> Optional[User]:
        user_doc = await db.get_db().users.find_one({"username": username})
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])
            return User(**user_doc)
        return None
    
    @staticmethod
    async def get_user_by_username_or_email(username_or_email: str) -> Optional[User]:
        # Try username first, then email
        user_doc = await db.get_db().users.find_one({"username": username_or_email})
        if not user_doc:
            user_doc = await db.get_db().users.find_one({"email": username_or_email})
        
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])
            return User(**user_doc)
        return None
    
    @staticmethod
    async def get_all_users() -> List[User]:
        user_docs = await db.get_db().users.find({}).to_list(length=None)
        users = []
        for user_doc in user_docs:
            user_doc["id"] = str(user_doc["_id"])
            users.append(User(**user_doc))
        return users

        
    @staticmethod
    async def update_user(user_id: str, update_data: UserUpdate) -> Optional[User]:
        update_doc = {"updated_at": datetime.utcnow()}
        
        if update_data.username is not None:
            update_doc["username"] = update_data.username
        if update_data.is_active is not None:
            update_doc["is_active"] = update_data.is_active
            
        result = await db.get_db().users.update_one(
            {"_id": ObjectId(user_id)}, 
            {"$set": update_doc}
        )
        
        if result.modified_count > 0:
            return await UserRepository.get_user_by_id(user_id)
        return None
    
    @staticmethod
    async def verify_user(user_id: str) -> bool:
        result = await db.get_db().users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_verified": True, "updated_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    @staticmethod
    async def update_password(user_id: str, new_password_hash: str) -> bool:
        result = await db.get_db().users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password_hash": new_password_hash, "updated_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    @staticmethod
    async def delete_user(user_id: str) -> bool:
        result = await db.get_db().users.delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0