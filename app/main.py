from contextlib import asynccontextmanager
from fastapi import FastAPI, Request ,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.core.database import db
from app.core.config import settings
from app.core.logging import setup_logging
from app.api.v1.api import api_router
from app.middleware.logging import LoggingMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.exceptions.handlers import (
    http_exception_handler, 
    validation_exception_handler, 
    general_exception_handler
)
from app.services.token_blacklist import token_blacklist

# Initialize logging first
logger = setup_logging()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect_db()
    logger.info("Database connected")
    
    # Connect to Redis for token blacklisting
    redis_connected = await token_blacklist.connect()
    if redis_connected:
        logger.info("Redis connected for token blacklisting")
    else:
        logger.warning("Redis connection failed - token blacklisting disabled")
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("Shutting down B2C Authentication API")
    await db.close_db()
    await token_blacklist.disconnect()
    logger.info("Database and Redis connections closed")

# Create FastAPI app
app = FastAPI(
    title="B2C Authentication API",
    description="Complete B2C authentication system with OTP verification",
    version="1.0.0",
    lifespan=lifespan
)

# Set up rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add standardized exception handlers
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(ValueError, validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

# Add logging middleware FIRST
app.add_middleware(LoggingMiddleware)

# Add Request ID middleware for tracing
app.add_middleware(RequestIDMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # Explicit list: ["https://myapp.com"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Be specific
    allow_headers=["Authorization", "Content-Type"],  # Be specific
)



app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    logger.info("Root endpoint accessed")
    return {"message": "B2C Authentication API", "version": "1.0.0"}