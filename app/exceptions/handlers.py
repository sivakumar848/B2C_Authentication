from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from app.schemas.error import ErrorResponse, ValidationErrorResponse
from app.utils.helpers import utc_now
import traceback

async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Standard HTTP exception handler"""
    request_id = getattr(request.state, 'request_id', None)
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.__class__.__name__,
            message=exc.detail,
            request_id=request_id,
            timestamp=utc_now().isoformat()
        ).model_dump()
    )

async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Standard validation exception handler"""
    request_id = getattr(request.state, 'request_id', None)
    
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="ValidationError",
            message="Validation failed",
            request_id=request_id,
            timestamp=utc_now().isoformat()
        ).model_dump()
    )

async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """General exception handler for unexpected errors"""
    request_id = getattr(request.state, 'request_id', None)
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred",
            request_id=request_id,
            timestamp=utc_now().isoformat()
        ).model_dump()
    )
