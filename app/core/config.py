from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional, Dict, Any

class Settings(BaseSettings):
    # Database
    mongodb_url: str = "mongodb+srv://sivakumar:12345@cluster0.wsezdm4.mongodb.net/?appName=Cluster0"
    database_name: str = "b2c_auth"
    
    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # AWS Cognito Configuration
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    cognito_client_secret: Optional[str] = None
    
    # JWT Configuration
    # For HS256, use a simple secret key string
    secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # AWS DynamoDB Configuration (if using DynamoDB instead of MongoDB)
    dynamodb_table_prefix: str = "b2c_auth_"
    
    # AWS SES Configuration (for emails)
    ses_region: str = "us-east-1"
    ses_sender_email: Optional[str] = None
    
    # AWS S3 Configuration (for file storage)
    s3_bucket_name: Optional[str] = None
    s3_region: str = "us-east-1"
    
    # OTP Configuration (can be used with AWS Pinpoint or SES)
    otp_expiry_minutes: int = 10
    
    # CORS Configuration
    cors_origins: list = ["*"]
    
    # Environment
    environment: str = "development"
    debug: bool = True
    
    # Email (for OTP sending - you'll need to configure actual email service)
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        extra='ignore'  # Ignore extra environment variables
    )

settings = Settings()