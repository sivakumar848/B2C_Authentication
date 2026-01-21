from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.services.auth_service import AuthService
from app.repositories.user_repository import UserRepository
from app.repositories.auth_repository import AuthRepository
from app.schemas.auth import (
    OTPSendRequest, OTPVerifyRequest, SignupRequest,
    LoginRequest, TokenResponse, RefreshTokenRequest,
    ChangePasswordRequest, ResetPasswordRequest, ForgotPasswordRequest
)
from app.core.security import verify_token

# Create global limiter instance
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Dependency injection functions
def get_user_repository() -> UserRepository:
    return UserRepository()

def get_auth_repository() -> AuthRepository:
    return AuthRepository()

def get_auth_service(
    user_repo: UserRepository = Depends(get_user_repository),
    auth_repo: AuthRepository = Depends(get_auth_repository)
) -> AuthService:
    return AuthService(user_repo=user_repo, auth_repo=auth_repo)

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
@limiter.limit("3/minute")
async def send_otp(
    request: Request,
    otp_request: OTPSendRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.send_otp(otp_request)

@router.post("/verify-otp", summary="Verify OTP")
async def verify_otp(
    request: OTPVerifyRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.verify_otp(request)

@router.post("/signup", summary="Complete signup after OTP verification")
@limiter.limit("5/minute")
async def signup(
    request: Request,
    signup_request: SignupRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.signup(signup_request)

@router.post("/login", summary="Login with username/email and password")
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.login(login_request)

@router.post("/refresh", summary="Refresh access token")
@limiter.limit("5/minute")
async def refresh_token(
    request: Request,
    refresh_token_request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.refresh_token(refresh_token_request)

@router.post("/logout", summary="Logout and revoke refresh token")
@limiter.limit("10/minute")
async def logout(
    request: Request,
    refresh_token_request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.logout(refresh_token_request.refresh_token)

@router.post("/change-password", summary="Change user password")
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    change_password_request: ChangePasswordRequest,
    current_user: str = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.change_password(current_user, change_password_request)

@router.post("/forgot-password", summary="Send password reset OTP")
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    forgot_password_request: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.forgot_password(forgot_password_request)

@router.post("/reset-password", summary="Reset password with OTP")
@limiter.limit("3/minute")
async def reset_password(
    request: Request,
    reset_password_request: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    return await auth_service.reset_password(reset_password_request)