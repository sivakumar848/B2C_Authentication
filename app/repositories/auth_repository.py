from datetime import datetime, timedelta
from typing import Optional
from app.core.database import db
from app.core.config import settings
from app.core.logging import logger
from app.schemas.auth import OTPLog, RefreshTokenInDB

class AuthRepository:
    
    @staticmethod
    async def save_otp(email: str, otp: str) -> OTPLog:
        otp_doc = {
            "email": email,
            "otp": otp,
            "expiry_time": datetime.utcnow() + timedelta(minutes=settings.otp_expiry_minutes),
            "verified": False,
            "created_at": datetime.utcnow()
        }
        
        # Remove any existing OTP for this email
        await db.get_db().otp_logs.delete_many({"email": email, "verified": False})
        
        result = await db.get_db().otp_logs.insert_one(otp_doc)
        otp_doc["id"] = str(result.inserted_id)
        return OTPLog(**otp_doc)
    
    @staticmethod
    async def verify_otp(email: str, otp: str) -> bool:
        otp_doc = await db.get_db().otp_logs.find_one({
            "email": email,
            "otp": otp,
            "verified": False,
            "expiry_time": {"$gt": datetime.utcnow()}
        })
        
        if otp_doc:
            # Mark OTP as verified
            await db.get_db().otp_logs.update_one(
                {"_id": otp_doc["_id"]},
                {"$set": {"verified": True}}
            )
            return True
        return False
    
    @staticmethod
    async def save_refresh_token(user_id: str, refresh_token: str) -> RefreshTokenInDB:
        token_doc = {
            "user_id": user_id,
            "refresh_token": refresh_token,
            "expiry": datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days),
            "revoked": False,
            "created_at": datetime.utcnow()
        }
        
        result = await db.get_db().refresh_tokens.insert_one(token_doc)
        token_doc["id"] = str(result.inserted_id)
        return RefreshTokenInDB(**token_doc)
    
    @staticmethod
    async def get_refresh_token(refresh_token: str) -> Optional[RefreshTokenInDB]:
        token_doc = await db.get_db().refresh_tokens.find_one({
            "refresh_token": refresh_token,
            "revoked": False,
            "expiry": {"$gt": datetime.utcnow()}
        })
        
        if token_doc:
            token_doc["id"] = str(token_doc["_id"])
            return RefreshTokenInDB(**token_doc)
        return None
    
    @staticmethod
    async def revoke_refresh_token(refresh_token: str) -> bool:
        result = await db.get_db().refresh_tokens.update_one(
            {"refresh_token": refresh_token},
            {"$set": {"revoked": True}}
        )
        return result.modified_count > 0
    
    @staticmethod
    async def revoke_all_user_tokens(user_id: str) -> bool:
        result = await db.get_db().refresh_tokens.update_many(
            {"user_id": user_id, "revoked": False},
            {"$set": {"revoked": True}}
        )
        return result.modified_count > 0

    @staticmethod
    async def is_email_verified(email: str) -> bool:
        """Check if email has been verified through OTP"""
        otp_doc = await db.get_db().otp_logs.find_one({
        "email": email,
        "verified": True,
        "expiry_time": {"$gt": datetime.utcnow()}
        })
        return otp_doc is not None

    @staticmethod
    async def delete_otp(email: str):
        """Delete OTP after successful use"""
        try:
            await db.get_db().otp_logs.delete_one({"email": email})
            logger.info(f"OTP deleted for email: {email}")
        except Exception as e:
            logger.error(f"Error deleting OTP for {email}: {str(e)}")
            raise