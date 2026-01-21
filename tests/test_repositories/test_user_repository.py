import pytest
from app.repositories.user_repository import UserRepository
from app.repositories.auth_repository import AuthRepository
from bson import ObjectId

class TestUserRepository:
    """Test user repository methods"""
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_valid(self):
        """Test getting user by valid ID"""
        user_id = str(ObjectId())
        user = await UserRepository.get_user_by_id(user_id)
        assert user is not None
        assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_invalid(self):
        """Test getting user by invalid ID"""
        user = await UserRepository.get_user_by_id("invalid_id")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_get_user_by_email(self):
        """Test getting user by email"""
        user = await UserRepository.get_user_by_email("test@example.com")
        assert user is not None
        assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_create_user(self):
        """Test user creation"""
        from app.schemas.user import UserCreate
        user_data = UserCreate(
            email="test@example.com",
            username="testuser"
        )
        user = await UserRepository.create_user(user_data, "hashed_password")
        assert user.email == "test@example.com"
        assert user.username == "testuser"
        assert user.is_verified == False

class TestAuthRepository:
    """Test auth repository methods"""
    
    @pytest.mark.asyncio
    async def test_save_and_verify_otp(self):
        """Test OTP save and verification"""
        email = "test@example.com"
        otp = "123456"
        
        # Save OTP
        saved = await AuthRepository.save_otp(email, otp)
        assert saved is True
        
        # Verify OTP
        verified = await AuthRepository.verify_otp(email, otp)
        assert verified is True
        
        # Check email is verified
        is_verified = await AuthRepository.is_email_verified(email)
        assert is_verified is True
    
    @pytest.mark.asyncio
    async def test_verify_invalid_otp(self):
        """Test OTP verification with invalid code"""
        verified = await AuthRepository.verify_otp("test@example.com", "000000")
        assert verified is False
