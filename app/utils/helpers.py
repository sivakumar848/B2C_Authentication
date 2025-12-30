from datetime import datetime, timezone
from typing import Any, Dict

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def format_datetime(dt: datetime) -> str:
    return dt.isoformat()

def sanitize_input(text: str) -> str:
    """Basic input sanitization"""
    return text.strip() if text else ""

def validate_email_domain(email: str, allowed_domains: list = None) -> bool:
    """Validate email domain if restrictions are needed"""
    if not allowed_domains:
        return True
    
    domain = email.split('@')[-1]
    return domain in allowed_domains