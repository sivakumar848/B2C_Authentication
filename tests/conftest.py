import pytest
import asyncio
from httpx import AsyncClient
from app.main import app

@pytest.fixture(scope="session")
async def test_client():
    """Create a test client for the FastAPI app"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "email": "test@example.com",
        "username": "testuser",
        "password": "TestPassword123!"
    }

@pytest.fixture
def sample_otp_data():
    """Sample OTP data for testing"""
    return {
        "email": "test@example.com",
        "otp": "123456"
    }
