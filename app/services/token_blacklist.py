import redis.asyncio as redis
from typing import Optional
from app.core.config import settings
from app.core.logging import logger

class TokenBlacklist:
    """Redis-based token blacklisting for performance"""
    
    def __init__(self):
        self.redis = None
    
    async def connect(self):
        """Initialize Redis connection"""
        try:
            self.redis = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            logger.info("Connected to Redis for token blacklisting")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            return False
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
            logger.info("Redis connection closed")
    
    async def blacklist_token(self, token: str, expires_in: int = 3600):
        """Add token to blacklist with expiration"""
        if not self.redis:
            logger.error("Redis not connected")
            return False
        
        try:
            await self.redis.setex(
                f"blacklist:{token}",
                expires_in,
                "1"
            )
            logger.info(f"Token blacklisted: {token[:8]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist token: {str(e)}")
            return False
    
    async def is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        if not self.redis:
            logger.error("Redis not connected")
            return False
        
        try:
            result = await self.redis.exists(f"blacklist:{token}")
            if result:
                logger.info(f"Token check: {token[:8]} is blacklisted")
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {str(e)}")
            return False
    
    async def remove_blacklisted_token(self, token: str):
        """Remove token from blacklist (for testing)"""
        if not self.redis:
            logger.error("Redis not connected")
            return False
        
        try:
            await self.redis.delete(f"blacklist:{token}")
            logger.info(f"Token removed from blacklist: {token[:8]}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove token from blacklist: {str(e)}")
            return False

# Global instance
token_blacklist = TokenBlacklist()
