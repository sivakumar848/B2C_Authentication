from motor.motor_asyncio import AsyncIOMotorClient
from app.core.logging import logger
from app.core.config import settings

class Database:
    client: AsyncIOMotorClient = None
    
    @classmethod
    async def connect_db(cls):
        try:
            cls.client = AsyncIOMotorClient(settings.mongodb_url)
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise
    
    @classmethod
    async def close_db(cls):
        if cls.client:
            cls.client.close()
            logger.info("MongoDB connection closed")
            
    @classmethod
    def get_db(cls):
        if not cls.client:
            logger.error("Database client not initialized")
            raise Exception("Database not connected")
        return cls.client[settings.database_name]

db = Database()