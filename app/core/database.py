from motor.motor_asyncio import AsyncIOMotorClient
from app.core.logging import logger
from app.core.config import settings

class Database:
    client: AsyncIOMotorClient = None
    
    @classmethod
    async def connect_db(cls):
        try:
            cls.client = AsyncIOMotorClient(settings.mongodb_url)
            
            # Force connection attempt
            await cls.client.server_info()
            
            logger.info("Successfully connected to MongoDB")
            
            # Create indexes
            db = cls.client[settings.database_name]
            
            # Unique indexes for users
            await db.users.create_index("email", unique=True)
            await db.users.create_index("username", unique=True)
            
            # Indexes for OTP lookups
            await db.otp_logs.create_index([("email", 1), ("verified", 1)])
            await db.otp_logs.create_index("expiry_time", expireAfterSeconds=0)  # TTL index
            
            # Indexes for refresh tokens
            await db.refresh_tokens.create_index("refresh_token")
            await db.refresh_tokens.create_index("user_id")
            await db.refresh_tokens.create_index("expiry", expireAfterSeconds=0)  # TTL index
            
            logger.info("Database connected and indexes created")
            
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