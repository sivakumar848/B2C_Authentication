from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class TokenData:
    def __init__(self, user_id: str, email: Optional[str] = None, **kwargs):
        self.user_id = user_id
        self.email = email
        self.extra = kwargs

def create_access_token(
    subject: Union[str, Any], 
    expires_delta: Optional[timedelta] = None,
    **extra_data
) -> str:
    """
    Create a new JWT access token
    
    Args:
        subject: The subject (usually user ID) for the token
        expires_delta: Optional timedelta for token expiration
        **extra_data: Additional data to include in the token
        
    Returns:
        str: Encoded JWT token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode = {
        "exp": expire, 
        "sub": str(subject), 
        "type": "access",
        "iat": datetime.utcnow(),
        **extra_data
    }
    
    return jwt.encode(
        to_encode, 
        settings.secret_key, 
        algorithm=settings.algorithm
    )

def create_refresh_token(
    subject: Union[str, Any], 
    **extra_data
) -> str:
    """
    Create a new JWT refresh token
    
    Args:
        subject: The subject (usually user ID) for the token
        **extra_data: Additional data to include in the token
        
    Returns:
        str: Encoded JWT refresh token
    """
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode = {
        "exp": expire, 
        "sub": str(subject), 
        "type": "refresh",
        "iat": datetime.utcnow(),
        **extra_data
    }
    
    return jwt.encode(
        to_encode, 
        settings.secret_key, 
        algorithm=settings.algorithm
    )

def verify_token(token: str) -> dict:
    """
    Verify a JWT token and return its payload
    
    Args:
        token: JWT token to verify
        
    Returns:
        dict: Decoded token payload
        
    Raises:
        ValueError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate a password hash"""
    return pwd_context.hash(password)

def generate_otp(length: int = 6) -> str:
    """
    Generate a random OTP
    
    Args:
        length: Length of the OTP (default: 6)
        
    Returns:
        str: Generated OTP
    """
    import random
    if length < 4:
        raise ValueError("OTP length must be at least 4")
    return ''.join(random.choices('0123456789', k=length))