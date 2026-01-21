from typing import Optional
from datetime import datetime, timedelta
from bson import ObjectId
from bson.errors import InvalidId
from app.core.database import db
from app.core.config import settings
from app.core.logging import logger
from app.utils.helpers import utc_now

class AuthRepository:
    
    @staticmethod
    async def save_otp(email: str, otp: str) -> bool:
        """Save OTP to database"""
        try:
            otp_doc = {
                "email": email,
                "otp": otp,
                "created_at": utc_now(),
                "expiry_time": utc_now() + timedelta(minutes=settings.otp_expiry_minutes),
                "verified": False
            }
            await db.get_db().otp_logs.insert_one(otp_doc)
            return True
        except Exception as e:
            logger.error(f"Failed to save OTP: {str(e)}")
            return False
    
    @staticmethod
    async def verify_otp(email: str, otp: str) -> bool:
        """Verify OTP and mark as used"""
        try:
            # Find unverified OTP for this email
            otp_doc = await db.get_db().otp_logs.find_one({
                "email": email,
                "otp": otp,
                "verified": False,
                "expiry_time": {"$gt": utc_now()}
            })
            
            if not otp_doc:
                return False
            
            # Mark OTP as verified
            result = await db.get_db().otp_logs.update_one(
                {"_id": otp_doc["_id"]},
                {"$set": {"verified": True, "updated_at": utc_now()}}
            )
            
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to verify OTP: {str(e)}")
            return False
    
    @staticmethod
    async def is_email_verified(email: str) -> bool:
        """Check if email has been verified through OTP"""
        try:
            # Check if there's any verified OTP for this email
            otp_doc = await db.get_db().otp_logs.find_one({
                "email": email,
                "verified": True
            })
            return otp_doc is not None
        except Exception as e:
            logger.error(f"Failed to check email verification: {str(e)}")
            return False
    
    @staticmethod
    async def delete_otp(email: str) -> bool:
        """Delete all OTPs for this email after successful signup"""
        try:
            result = await db.get_db().otp_logs.delete_many({"email": email})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete OTP: {str(e)}")
            return False
    
    @staticmethod
    async def save_refresh_token(user_id: str, refresh_token: str, expiry_days: int = 7) -> bool:
        """Save refresh token to database"""
        try:
            oid = ObjectId(user_id)
        except InvalidId:
            return False
            
        token_doc = {
            "user_id": oid,
            "refresh_token": refresh_token,
            "created_at": utc_now(),
            "expiry_time": utc_now() + timedelta(days=expiry_days),
            "revoked": False
        }
        await db.get_db().refresh_tokens.insert_one(token_doc)
        return True
    
    @staticmethod
    async def get_refresh_token(refresh_token: str) -> Optional[dict]:
        """Get refresh token from database"""
        try:
            token_doc = await db.get_db().refresh_tokens.find_one({
                "refresh_token": refresh_token,
                "revoked": False,
                "expiry_time": {"$gt": utc_now()}
            })
            return token_doc
        except Exception as e:
            logger.error(f"Failed to get refresh token: {str(e)}")
            return None
    
    @staticmethod
    async def revoke_refresh_token(refresh_token: str) -> bool:
        """Revoke a specific refresh token"""
        try:
            result = await db.get_db().refresh_tokens.update_one(
                {"refresh_token": refresh_token},
                {"$set": {"revoked": True, "updated_at": utc_now()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to revoke refresh token: {str(e)}")
            return False
    
    @staticmethod
    async def revoke_all_user_tokens(user_id: str) -> bool:
        """Revoke all refresh tokens for a user"""
        try:
            oid = ObjectId(user_id)
        except InvalidId:
            return False
            
        result = await db.get_db().refresh_tokens.update_many(
            {"user_id": oid},
            {"$set": {"revoked": True, "updated_at": utc_now()}}
        )
        return result.modified_count > 0
