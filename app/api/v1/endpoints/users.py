from fastapi import APIRouter, Depends, HTTPException, status
from app.repositories.user_repository import UserRepository
from app.schemas.user import UserResponse, UserUpdate
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()

@router.get("/me", summary="Get current user profile", response_model=UserResponse)
async def get_current_user_profile(current_user: str = Depends(get_current_user)):
    user = await UserRepository.get_user_by_id(current_user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        is_verified=user.is_verified,
        is_active=user.is_active,
        created_at=user.created_at
    )

@router.put("/me", summary="Update current user profile", response_model=UserResponse)
async def update_current_user_profile(
    update_data: UserUpdate,
    current_user: str = Depends(get_current_user)
):
    user = await UserRepository.update_user(current_user, update_data)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        is_verified=user.is_verified,
        is_active=user.is_active,
        created_at=user.created_at
    )