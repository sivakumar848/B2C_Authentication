
## Prerequisites

- Python 3.9+
- MongoDB (local or cloud instance)
- pip or poetry

## Installation

### 1. Clone the repository
sh
git clone <repository-url>
cd B2C_Authentation_API### 2. Create a virtual environment

# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate### 3. Install dependencies

pip install -r requirements.txt### 4. Environment Variables

Create a `.env` file in the root directory:
nv
# Database
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=b2c_auth_db

# JWT Configuration
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
APP_NAME=B2C Authentication API
DEBUG=True
ENVIRONMENT=development

# CORS (optional)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080**Important**: Never commit the `.env` file. Use `.env.example` as a template.

### 5. Run the application

# Development mode
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000The API will be available at:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout

### Users

- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update current user profile
- `DELETE /api/v1/users/me` - Delete current user account

## Usage Examples

### Register a User

curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "full_name": "John Doe"
  }'
### Login
ash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'### Access Protected Endpoint

curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"## Running with Docker

### Build the image

docker build -t b2c-auth-api .### Run the container

docker run -d \
  --name b2c-auth-api \
  -p 8000:8000 \
  --env-file .env \
  b2c-auth-api### Using Docker Compose (if available)

docker-compose up -d## Testing

Run tests with pytest:

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py## Development

### Code Style

This project follows PEP 8 style guidelines. Consider using:
- `black` for code formatting
- `flake8` for linting
- `mypy` for type checking

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- ✅ Passwords are hashed using bcrypt
- ✅ JWT tokens for stateless authentication
- ✅ Input validation with Pydantic
- ✅ Environment variables for sensitive data
- ✅ CORS configuration support
- ⚠️ Always use HTTPS in production
- ⚠️ Keep SECRET_KEY secure and never commit it
- ⚠️ Regularly update dependencies

## Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MONGODB_URL` | MongoDB connection string | Yes | - |
| `DATABASE_NAME` | Database name | Yes | `b2c_auth_db` |
| `SECRET_KEY` | JWT secret key | Yes | - |
| `ALGORITHM` | JWT algorithm | No | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | No | `30` |
| `DEBUG` | Debug mode | No | `False` |
| `ENVIRONMENT` | Environment name | No | `development` |

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue on the GitHub repository.

## Author

Your Name / Your Organization