from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import db
from app.core.logging import setup_logging
from app.api.v1.api import api_router
from app.middleware.logging import LoggingMiddleware

# Initialize logging first
logger = setup_logging()

# Create FastAPI app
app = FastAPI(
    title="B2C Authentication API",
    description="Complete B2C authentication system with OTP verification",
    version="1.0.0"
)

# Add logging middleware FIRST
app.add_middleware(LoggingMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await db.connect_db()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down B2C Authentication API")
    await db.close_db()
    logger.info("Database connection closed")

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    logger.info("Root endpoint accessed")
    return {"message": "B2C Authentication API", "version": "1.0.0"}