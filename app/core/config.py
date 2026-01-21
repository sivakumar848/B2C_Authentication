from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional, Dict, Any

class Settings(BaseSettings):
    # Database
    mongodb_url: str  # Required - must be set via MONGODB_URL environment variable
    database_name: str = "b2c_auth"
    
    # JWT Configuration
    # For HS256, use a secure secret key string
    secret_key: str  # Required - must be set via SECRET_KEY environment variable
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # OTP Configuration
    otp_expiry_minutes: int = 10

    # Redis Configuration (for token blacklisting)
    redis_url: str = "redis://localhost:6379"
    
    # CORS Configuration
    cors_origins: list = ["https://yourfrontend.com", "https://admin.yourapp.com"]
    
    # Environment
    environment: str = "development"
    debug: bool = True
    
    # Email (for OTP sending - you'll need to configure actual email service)
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    
    # Gmail SMTP configuration
    # For Gmail, you need to:
    # 1. Enable 2-Step Verification in your Google Account
    # 2. Use an App Password (16 characters recommended)
    # 3. Allow less secure apps access in your Google Account
    # 4. Update the smtp_username to your email address
    # 5. Update the smtp_password to your app password
    
    # Note: The current configuration uses regular SMTP which may not work with Gmail's security
    # Consider using Google's App Passwords for better security
    
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        extra='ignore'  # Ignore extra environment variables
    )

settings = Settings()