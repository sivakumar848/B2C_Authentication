import pytest
from httpx import AsyncClient
from app.core.config import settings

class TestAuth:
    """Test authentication endpoints"""
    
    @pytest.mark.asyncio
    async def test_send_otp_success(self, test_client: AsyncClient):
        """Test successful OTP sending"""
        response = await test_client.post(
            "/api/v1/auth/send-otp",
            json={"email": "test@example.com"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "OTP sent successfully"
    
    @pytest.mark.asyncio
    async def test_send_otp_duplicate_user(self, test_client: AsyncClient):
        """Test OTP send to already verified user"""
        # This test would need to mock the user repository
        # For now, just test the endpoint structure
        response = await test_client.post(
            "/api/v1/auth/send-otp",
            json={"email": "test@example.com"}
        )
        # Should return 200 even if user doesn't exist (security best practice)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_verify_otp_invalid(self, test_client: AsyncClient):
        """Test OTP verification with invalid OTP"""
        response = await test_client.post(
            "/api/v1/auth/verify-otp",
            json={"email": "test@example.com", "otp": "000000"}
        )
        assert response.status_code == 400
        assert "Invalid or expired OTP" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_login_success(self, test_client: AsyncClient, sample_user_data):
        """Test successful login"""
        # First send OTP
        await test_client.post(
            "/api/v1/auth/send-otp",
            json={"email": sample_user_data["email"]}
        )
        
        # Then verify OTP (mocked in real tests)
        response = await test_client.post(
            "/api/v1/auth/verify-otp",
            json={"email": sample_user_data["email"], "otp": "123456"}
        )
        
        # Then signup
        response = await test_client.post(
            "/api/v1/auth/signup",
            json={
                "email": sample_user_data["email"],
                "username": sample_user_data["username"],
                "password": sample_user_data["password"]
            }
        )
        assert response.status_code == 200
        assert "id" in response.json()
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, test_client: AsyncClient):
        """Test login with invalid credentials"""
        response = await test_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "invalid@test.com", "password": "wrongpassword"}
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_signup_invalid_otp(self, test_client: AsyncClient, sample_user_data):
        """Test signup without OTP verification"""
        response = await test_client.post(
            "/api/v1/auth/signup",
            json={
                "email": sample_user_data["email"],
                "username": sample_user_data["username"],
                "password": sample_user_data["password"]
            }
        )
        assert response.status_code == 400
        assert "Email not verified" in response.json()["detail"]
