import pytest
from app.repositories.auth_repository import AuthRepository

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
    
    @pytest.mark.asyncio
    async def test_refresh_token_lifecycle(self):
        """Test refresh token save and revoke"""
        user_id = str(ObjectId())
        refresh_token = "test_refresh_token"
        
        # Save token
        saved = await AuthRepository.save_refresh_token(user_id, refresh_token)
        assert saved is True
        
        # Get token
        token = await AuthRepository.get_refresh_token(refresh_token)
        assert token is not None
        assert token["user_id"] == user_id
        
        # Revoke token
        revoked = await AuthRepository.revoke_refresh_token(refresh_token)
        assert revoked is True
        
        # Verify token is revoked
        revoked_token = await AuthRepository.get_refresh_token(refresh_token)
        assert revoked_token is None
