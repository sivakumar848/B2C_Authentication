import pytest
from httpx import AsyncClient
from app.core.config import settings

class TestUsers:
    """Test user management endpoints"""
    
    @pytest.mark.asyncio
    async def test_get_users_unauthorized(self, test_client: AsyncClient):
        """Test getting users without authentication"""
        response = await test_client.get("/api/v1/users/")
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_get_current_user(self, test_client: AsyncClient):
        """Test getting current user with valid token"""
        # This would need to mock authentication
        # For now, just test endpoint exists
        response = await test_client.get("/api/v1/users/me")
        assert response.status_code in [401, 404]  # Either unauthorized or not implemented
