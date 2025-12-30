from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.services.auth_service import AuthService
from app.schemas.auth import (
    OTPSendRequest, OTPVerifyRequest, SignupRequest,
    LoginRequest, TokenResponse, RefreshTokenRequest,
    ChangePasswordRequest,ResetPasswordRequest,ForgotPasswordRequest
)
from app.core.security import verify_token

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        user_id = payload.get("sub")
        return user_id
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

@router.post("/send-otp", summary="Send OTP to email")
async def send_otp(request: OTPSendRequest):
    return await AuthService.send_otp(request)

@router.post("/verify-otp", summary="Verify OTP")
async def verify_otp(request: OTPVerifyRequest):
    return await AuthService.verify_otp(request)

@router.post("/signup", summary="Complete signup after OTP verification")
async def signup(request: SignupRequest):
    return await AuthService.signup(request)

@router.post("/login", summary="Login with username/email and password")
async def login(request: LoginRequest):
    return await AuthService.login(request)

@router.post("/refresh", summary="Refresh access token")
async def refresh_token(request: RefreshTokenRequest):
    return await AuthService.refresh_token(request)

@router.post("/logout", summary="Logout and revoke refresh token")
async def logout(
    request: RefreshTokenRequest,
    current_user: str = Depends(get_current_user)
):
    return await AuthService.logout(request.refresh_token)

# @router.post("/change-password", summary="Change user password")
# async def change_password(
#     request: ChangePasswordRequest,
#     current_user: str = Depends(get_current_user)
# ):
#     return await AuthService.change_password(current_user, request)

# Add these endpoints to auth.py
@router.post("/forgot-password", summary="Send password reset OTP")
async def forgot_password(request: OTPSendRequest):
    return await AuthService.forgot_password(request)

@router.post("/reset-password", summary="Reset password with OTP")
async def reset_password(request: ResetPasswordRequest):
    return await AuthService.reset_password(request)