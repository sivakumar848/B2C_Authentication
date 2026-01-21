import pytest

class TestHealth:
    """Test health check endpoints"""
    
    @pytest.mark.asyncio
    async def test_health_endpoint(self, test_client):
        """Test basic health check"""
        response = await test_client.get("/api/v1/health/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_ready_endpoint_with_db(self, test_client):
        """Test readiness check with database"""
        response = await test_client.get("/api/v1/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"
        assert "database" in response.json()
    
    @pytest.mark.asyncio
    async def test_request_id_header(self, test_client):
        """Test that request ID is returned in headers"""
        response = await test_client.get("/api/v1/health/health")
        assert "x-request-id" in response.headers
        assert response.headers["x-request-id"] is not None
