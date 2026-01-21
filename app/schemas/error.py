from pydantic import BaseModel
from typing import Optional, List, Any

class ErrorDetail(BaseModel):
    field: Optional[str] = None
    message: str

class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[List[ErrorDetail]] = None
    request_id: Optional[str] = None
    timestamp: Optional[str] = None

class ValidationErrorDetail(BaseModel):
    field: str
    message: str
    value: Any

class ValidationErrorResponse(BaseModel):
    error: str = "ValidationError"
    message: str
    details: Optional[List[ValidationErrorDetail]] = None
    request_id: Optional[str] = None
    timestamp: Optional[str] = None
