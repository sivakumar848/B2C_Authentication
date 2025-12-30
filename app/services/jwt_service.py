import os
import time
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwk, jwt as jose_jwt
from jose.utils import base64url_decode
from app.core.config import settings
from app.services.email_service import email_service

class JWTService:
    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_days = settings.refresh_token_expire_days
        
        # OAuth2 scheme for token authentication
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a new access token
        
        Args:
            data: Dictionary containing the data to encode in the token
            expires_delta: Optional timedelta for token expiration
            
        Returns:
            str: Encoded JWT token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """
        Create a new refresh token
        
        Args:
            data: Dictionary containing the data to encode in the token
            
        Returns:
            str: Encoded JWT refresh token
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        })
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a JWT token and return its payload
        
        Args:
            token: JWT token to verify
            
        Returns:
            Dict: Decoded token payload if valid
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # First, try to verify with the local secret key
            try:
                payload = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    options={"verify_aud": False}
                )
                return payload
                
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jwt.JWTError as e:
                # If local verification fails, try with Cognito
                return self._verify_cognito_token(token)
                
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def _verify_cognito_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a JWT token issued by AWS Cognito
        
        Args:
            token: JWT token to verify
            
        Returns:
            Dict: Decoded token payload if valid
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Get the key ID from the token header
            header = jwt.get_unverified_header(token)
            kid = header["kid"]
            
            # Get the public key from Cognito
            jwks_url = f"https://cognito-idp.{settings.aws_region}.amazonaws.com/{settings.cognito_user_pool_id}/.well-known/jwks.json"
            jwks_client = jwk.construct(jwks_url)
            
            # Get the key from the JWKS
            key = jwks_client.get_signing_key(kid)
            
            # Verify the token
            payload = jose_jwt.decode(
                token,
                key,
                algorithms=[self.algorithm],
                audience=settings.cognito_client_id,
                options={"verify_aud": True, "verify_at_hash": False},
            )
            
            return payload
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    async def send_verification_email(self, email: str, user_id: str, username: str) -> None:
        """
        Send an email verification link to the user
        
        Args:
            email: User's email address
            user_id: User's unique ID
            username: User's username
        """
        # Create a verification token
        token = self.create_access_token(
            {"sub": user_id, "email": email},
            expires_delta=timedelta(hours=24)  # 24-hour expiration
        )
        
        # Create verification URL
        verification_url = f"{settings.app_base_url}/verify-email?token={token}"
        
        # Send verification email using SES
        await email_service.send_verification_email(
            to_address=email,
            verification_url=verification_url,
            user_name=username
        )
    
    async def send_password_reset_email(self, email: str, user_id: str, username: str) -> None:
        """
        Send a password reset email to the user
        
        Args:
            email: User's email address
            user_id: User's unique ID
            username: User's username
        """
        # Create a password reset token
        token = self.create_access_token(
            {"sub": user_id, "email": email, "purpose": "password_reset"},
            expires_delta=timedelta(hours=1)  # 1-hour expiration
        )
        
        # Create reset password URL
        reset_url = f"{settings.app_base_url}/reset-password?token={token}"
        
        # Send password reset email using SES
        await email_service.send_password_reset_email(
            to_address=email,
            reset_url=reset_url,
            user_name=username
        )

# Create a singleton instance
jwt_service = JWTService()
