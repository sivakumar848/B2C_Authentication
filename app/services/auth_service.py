from datetime import datetime
from typing import Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import HTTPException, status
from app.repositories.user_repository import UserRepository
from app.repositories.auth_repository import AuthRepository
from app.core.security import (
    generate_otp, verify_password, get_password_hash,
    create_access_token, create_refresh_token, verify_token
)
from app.core.config import settings
from app.core.logging import logger
from app.schemas.auth import (
    OTPSendRequest, OTPVerifyRequest, SignupRequest, 
    LoginRequest, TokenResponse, RefreshTokenRequest,
    ChangePasswordRequest,ResetPasswordRequest,ForgotPasswordRequest
)
from app.schemas.user import UserResponse

class AuthService:
    
    @staticmethod
    async def send_otp(request: OTPSendRequest) -> dict:
        logger.info(f"Sending OTP to email: {request.email}")
        
        # Check if user already exists
        existing_user = await UserRepository.get_user_by_email(request.email)
        if existing_user and existing_user.is_verified:
            logger.warning(f"Attempted OTP send for already verified user: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists and is verified"
            )
        
        # Generate and save OTP
        otp = generate_otp()
        await AuthRepository.save_otp(request.email, otp)
        
        # Send OTP via email (implement actual email sending)
        await AuthService._send_otp_email(request.email, otp)
        
        logger.info(f"OTP sent successfully to: {request.email}")
        return {"message": "OTP sent successfully"}
    
    @staticmethod
    async def verify_otp(request: OTPVerifyRequest) -> dict:
        logger.info(f"Verifying OTP for email: {request.email}")
        
        is_valid = await AuthRepository.verify_otp(request.email, request.otp)
        
        if not is_valid:
            logger.warning(f"Invalid OTP verification attempt for: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        logger.info(f"OTP verified successfully for: {request.email}")
        return {"message": "OTP verified successfully"}
    
    @staticmethod
    async def signup(request: SignupRequest) -> UserResponse:
        logger.info(f"Signup attempt for email: {request.email}, username: {request.username}")
        
        # Check if email has been verified through OTP
        email_verified = await AuthRepository.is_email_verified(request.email)
        
        if not email_verified:
            logger.warning(f"Signup attempt without OTP verification: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email not verified. Please verify OTP first."
            )
        
        # Check if user already exists with this email
        existing_user = await UserRepository.get_user_by_email(request.email)
        if existing_user:
            logger.warning(f"Signup attempt for existing email: {request.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        
        # Check if username is available
        existing_user = await UserRepository.get_user_by_username(request.username)
        if existing_user:
            logger.warning(f"Signup attempt with taken username: {request.username}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        # Create user
        password_hash = get_password_hash(request.password)
        user = await UserRepository.create_user(request, password_hash)
        
        # User is already marked as verified in create_user, but let's ensure it
        if not user.is_verified:
            await UserRepository.verify_user(user.id)
            user.is_verified = True
        
        logger.info(f"User created successfully: {user.email} (ID: {user.id})")
        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            is_verified=user.is_verified,
            is_active=user.is_active,
            created_at=user.created_at
        )
    
    @staticmethod
    async def login(request: LoginRequest) -> TokenResponse:
        logger.info(f"Login attempt for: {request.username_or_email}")
        
        # Find user by username or email
        user = await UserRepository.get_user_by_username_or_email(request.username_or_email)
        
        if not user or not verify_password(request.password, user.password_hash):
            logger.warning(f"Failed login attempt for: {request.username_or_email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not user.is_verified:
            logger.warning(f"Login attempt for unverified user: {request.username_or_email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account not verified"
            )
        
        if not user.is_active:
            logger.warning(f"Login attempt for deactivated user: {request.username_or_email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        # Generate tokens
        access_token = create_access_token(subject=user.id)
        refresh_token = create_refresh_token(subject=user.id)
        
        # Save refresh token
        await AuthRepository.save_refresh_token(user.id, refresh_token)
        
        logger.info(f"Login successful for user: {user.email} (ID: {user.id})")
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    # ADD THE refresh_token METHOD HERE (between lines 154 and 156)
    @staticmethod
    async def refresh_token(request: RefreshTokenRequest) -> TokenResponse:
        logger.info("Token refresh request received")
        
        # Verify refresh token
        try:
            payload = verify_token(request.refresh_token)
            if payload.get("type") != "refresh":
                raise ValueError("Invalid token type")
        except ValueError as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user_id = payload.get("sub")
        
        # Check if refresh token exists in database and is not revoked
        stored_token = await AuthRepository.get_refresh_token(request.refresh_token)
        if not stored_token:
            logger.warning(f"Refresh token not found or revoked for user: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token revoked or expired"
            )
        
        # Generate new tokens
        new_access_token = create_access_token(subject=user_id)
        new_refresh_token = create_refresh_token(subject=user_id)
        
        # Revoke old refresh token and save new one
        await AuthRepository.revoke_refresh_token(request.refresh_token)
        await AuthRepository.save_refresh_token(user_id, new_refresh_token)
        
        logger.info(f"Tokens refreshed successfully for user: {user_id}")
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token
        )

    @staticmethod
    async def logout(refresh_token: str) -> dict:
        logger.info("Logout request received")
        await AuthRepository.revoke_refresh_token(refresh_token)
        logger.info("User logged out successfully")
        return {"message": "Logged out successfully"}
    
    @staticmethod
    async def change_password(user_id: str, request: ChangePasswordRequest) -> dict:
        logger.info(f"Password change request for user ID: {user_id}")
        
        # Get user
        user = await UserRepository.get_user_by_id(user_id)
        if not user:
            logger.warning(f"Password change attempt for non-existent user: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify current password
        if not verify_password(request.current_password, user.password_hash):
            logger.warning(f"Incorrect current password for user: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password and update
        new_password_hash = get_password_hash(request.new_password)
        success = await UserRepository.update_password(user_id, new_password_hash)
        
        if success:
            # Revoke all refresh tokens for security
            await AuthRepository.revoke_all_user_tokens(user_id)
            logger.info(f"Password changed successfully for user: {user.email}")
            return {"message": "Password changed successfully"}
        
        logger.error(f"Failed to update password for user: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )
    
    @staticmethod
    async def _send_otp_email(email: str, otp: str, otp_type: str = "verification"):
        logger.info(f"Sending {otp_type} OTP {otp} to {email}")
    
        subject = "Your OTP Code"
        if otp_type == "password_reset":
            subject = "Password Reset OTP"
    
        body = f"Your OTP code is: {otp}. It expires in {settings.otp_expiry_minutes} minutes."
        if otp_type == "password_reset":
            body = f"Your password reset OTP code is: {otp}. It expires in {settings.otp_expiry_minutes} minutes."
    
        # Only send email if SMTP credentials are configured
        if settings.smtp_username and settings.smtp_password:
            msg = MIMEMultipart()
            msg['From'] = settings.smtp_username
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
        
            server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
            server.starttls()
            server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
            server.quit()
        
            logger.info(f"OTP email sent successfully to {email}")
        else:
            # For development/testing - just log the OTP
            otp_message = f"DEVELOPMENT MODE - {otp_type.upper()} OTP for {email}: {otp}"
            logger.warning(f"SMTP not configured. {otp_message}")


    @staticmethod
    async def forgot_password(request: ForgotPasswordRequest) -> dict:
        logger.info(f"Password reset request for email: {request.email}")
    
        # Check if user exists
        user = await UserRepository.get_user_by_email(request.email)
        if not user:
            logger.warning(f"Password reset attempt for non-existent email: {request.email}")
            # Debug: Log all existing users (remove this in production!)
            all_users = await UserRepository.get_all_users()
            logger.info(f"Existing users in DB: {[u.email for u in all_users]}")
            # Don't reveal if email exists or not for security
            return {"message": "If the email exists, a reset OTP has been sent"}
    
        if not user.is_verified:
            logger.warning(f"Password reset attempt for unverified user: {request.email}")
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account not verified"
        )
    
        # Generate and save OTP
        otp = generate_otp()
        logger.info(f"Generated OTP: {otp} for {request.email}")  # Debug log
        await AuthRepository.save_otp(request.email, otp)
    
        # Send OTP via email
        await AuthService._send_otp_email(request.email, otp, "password_reset")
    
        logger.info(f"Password reset OTP sent to: {request.email}")
        return {"message": "Password reset OTP sent successfully"}

    @staticmethod
    async def reset_password(request: ResetPasswordRequest) -> dict:
        logger.info(f"Password reset attempt for email: {request.email}")
    
    # Verify OTP
        is_valid = await AuthRepository.verify_otp(request.email, request.otp)
        if not is_valid:
            logger.warning(f"Invalid OTP for password reset: {request.email}")
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )
    
        # Get user
        user = await UserRepository.get_user_by_email(request.email)
        if not user:
            logger.warning(f"Password reset for non-existent user: {request.email}")
            raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
        # Hash new password and update
        new_password_hash = get_password_hash(request.new_password)
        success = await UserRepository.update_password(user.id, new_password_hash)
    
        if success:
        # Revoke all refresh tokens for security
            await AuthRepository.revoke_all_user_tokens(user.id)
        # Mark OTP as used by deleting it
            await AuthRepository.delete_otp(request.email)
        
        logger.info(f"Password reset successful for user: {request.email}")
        return {"message": "Password reset successfully"}
    
        logger.error(f"Failed to reset password for user: {request.email}")
        raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to reset password"
        )
