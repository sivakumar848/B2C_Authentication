from fastapi import APIRouter
from app.core.database import db

router = APIRouter()

@router.get("/health")
async def health():
    """Basic health check"""
    return {"status": "healthy"}

@router.get("/ready")
async def ready():
    """Readiness check - verifies dependencies"""
    try:
        await db.client.server_info()
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return {"status": "not ready", "database": str(e)}
