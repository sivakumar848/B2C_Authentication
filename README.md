# B2C Authentication API

A comprehensive B2C (Business-to-Consumer) authentication system built with FastAPI, featuring OTP-based registration and login, JWT token management, and secure user authentication with AWS integration support.

## 🚀 Features

- **OTP-based Authentication**: Secure email-based OTP verification for signup and password reset
- **JWT Token Management**: Access and refresh token implementation with automatic expiration
- **MongoDB Integration**: NoSQL database support with Motor async driver
- **AWS Services Integration**: Support for AWS Cognito, DynamoDB, and SES
- **Password Security**: bcrypt hashing for secure password storage
- **Email Integration**: Built-in email service for OTP delivery
- **User Profile Management**: Complete user CRUD operations
- **Docker Support**: Containerized deployment ready with health checks
- **CORS Support**: Configurable Cross-Origin Resource Sharing
- **Logging Middleware**: Comprehensive request/response logging
- **Pydantic Validation**: Strong typing and input validation

## 📋 Prerequisites

- Python 3.11
- MongoDB (local or cloud instance) OR AWS DynamoDB
- pip package manager
- AWS Account (for AWS services integration - optional)

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd B2C_Authentation_API
```

### 2. Create a virtual environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Variables

Create a `.env` file in the root directory:

```env
# Database Configuration
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=b2c_auth_db

# JWT Configuration
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# AWS Cognito Configuration (optional)
COGNITO_USER_POOL_ID=your-cognito-user-pool-id
COGNITO_CLIENT_ID=your-cognito-client-id
COGNITO_CLIENT_SECRET=your-cognito-client-secret

# AWS DynamoDB Configuration (if using DynamoDB)
DYNAMODB_TABLE_PREFIX=b2c_auth_

# AWS SES Configuration (for emails)
AWS_SES_REGION=us-east-1

# Application Settings
APP_NAME=B2C Authentication API
DEBUG=True
ENVIRONMENT=development

# CORS Settings (optional)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080

# Email Configuration (if using SMTP instead of SES)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

> **Important**: Never commit the `.env` file. Consider using `.env.example` as a template.

### 5. Run the application

**Development mode:**
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Production mode:**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API will be available at:
- **API Base**: http://localhost:8000
- **Interactive API Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

## 📚 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/send-otp` | Send OTP to email for verification |
| `POST` | `/api/v1/auth/verify-otp` | Verify OTP code |
| `POST` | `/api/v1/auth/signup` | Complete signup after OTP verification |
| `POST` | `/api/v1/auth/login` | Login with email/username and password |
| `POST` | `/api/v1/auth/refresh` | Refresh access token using refresh token |
| `POST` | `/api/v1/auth/logout` | Logout and revoke refresh token |
| `POST` | `/api/v1/auth/forgot-password` | Send password reset OTP |
| `POST` | `/api/v1/auth/reset-password` | Reset password using OTP |

### User Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/users/me` | Get current user profile |
| `PUT` | `/api/v1/users/me` | Update current user profile |

## 💡 Usage Examples

### 1. Send OTP for Registration

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/send-otp" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

**Response:**
```json
{
  "message": "OTP sent successfully to your email",
  "otp_id": "abc123def456",
  "expires_in": 300
}
```

### 2. Verify OTP

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "otp": "123456"
  }'
```

**Response:**
```json
{
  "message": "OTP verified successfully",
  "verification_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 600
}
```

### 3. Complete Signup

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "johndoe",
    "password": "SecurePassword123!",
    "otp": "123456"
  }'
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "64a1b2c3d4e5f6789012345",
    "email": "user@example.com",
    "username": "johndoe",
    "is_verified": true,
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z"
  },
  "tokens": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 1800
  }
}
```

### 4. Login

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "64a1b2c3d4e5f6789012345",
    "email": "user@example.com",
    "username": "johndoe",
    "is_verified": true,
    "is_active": true
  },
  "tokens": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 1800
  }
}
```

### 5. Refresh Access Token

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  }'
```

**Response:**
```json
{
  "message": "Token refreshed successfully",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### 6. Logout

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -d '{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  }'
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

### 7. Forgot Password

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

**Response:**
```json
{
  "message": "Password reset OTP sent to your email",
  "otp_id": "def789ghi012",
  "expires_in": 300
}
```

### 8. Reset Password

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "otp": "654321",
    "new_password": "NewSecurePassword123!"
  }'
```

**Response:**
```json
{
  "message": "Password reset successful"
}
```

### 9. Get Current User Profile

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

**Response:**
```json
{
  "id": "64a1b2c3d4e5f6789012345",
  "email": "user@example.com",
  "username": "johndoe",
  "is_verified": true,
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 10. Update User Profile

**Request:**
```bash
curl -X PUT "http://localhost:8000/api/v1/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -d '{
    "username": "john_doe_updated"
  }'
```

**Response:**
```json
{
  "id": "64a1b2c3d4e5f6789012345",
  "email": "user@example.com",
  "username": "john_doe_updated",
  "is_verified": true,
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

## 📝 Error Response Format

All endpoints return consistent error responses:

```json
{
  "detail": "Error message description",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

## 🐳 Running with Docker

### Build the image

```bash
docker build -t b2c-auth-api .
```

### Run the container

```bash
docker run -d \
  --name b2c-auth-api \
  -p 8000:8000 \
  --env-file .env \
  b2c-auth-api
```

### Using Docker Compose (if available)

```bash
docker-compose up -d
```

## ☁️ AWS Integration

This API supports integration with various AWS services for enhanced functionality:

### AWS Cognito Integration
- **User Pool Management**: Integrate with AWS Cognito for user authentication
- **Federation Support**: Support for social logins and enterprise federation
- **MFA Support**: Multi-factor authentication capabilities

### AWS DynamoDB Integration
- **NoSQL Database**: Use DynamoDB as an alternative to MongoDB
- **Scalability**: Automatic scaling with AWS infrastructure
- **Performance**: Low-latency database operations

### AWS SES Integration
- **Email Delivery**: Reliable email delivery for OTP verification
- **Template Support**: Custom email templates
- **Analytics**: Email delivery tracking and analytics

### AWS Configuration Setup

1. **Create AWS Account**: Set up an AWS account if you don't have one
2. **Configure IAM**: Create appropriate IAM roles and policies
3. **Set up Services**: Configure Cognito, DynamoDB, and/or SES as needed
4. **Update Environment Variables**: Configure AWS credentials in your `.env` file

> **Note**: AWS integration is optional. The API works perfectly with local MongoDB and SMTP services.

## 🧪 Testing

Run tests with pytest:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py
```

## 🏗️ Project Structure

```
B2C_Authentation_API/
├── app/
│   ├── main.py                 # FastAPI application instance
│   ├── core/                   # Core functionality
│   │   ├── config.py          # Application configuration
│   │   ├── database.py        # Database connection
│   │   ├── security.py        # JWT and security utilities
│   │   └── logging.py         # Logging configuration
│   ├── api/v1/                # API version 1
│   │   ├── api.py            # API router
│   │   └── endpoints/         # API endpoints
│   │       ├── auth.py        # Authentication endpoints
│   │       └── users.py       # User management endpoints
│   ├── models/                # Database models
│   ├── schemas/               # Pydantic schemas
│   ├── services/              # Business logic services
│   ├── repositories/          # Data access layer
│   ├── middleware/            # Custom middleware
│   └── utils/                 # Utility functions
├── Dockerfile                 # Docker configuration
├── requirements.txt           # Python dependencies
└── README.md                 # This file
```

## 🔧 Development

### Code Style

This project follows PEP 8 style guidelines. Consider using:

- `black` for code formatting
- `flake8` for linting
- `mypy` for type checking

### Pre-commit Hooks (Recommended)

```bash
pip install pre-commit
pre-commit install
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔒 Security Considerations

- ✅ **Password Hashing**: Passwords are hashed using bcrypt
- ✅ **JWT Tokens**: Stateless authentication with access/refresh tokens
- ✅ **Input Validation**: Pydantic models for request validation
- ✅ **Environment Variables**: Sensitive data stored securely
- ✅ **CORS Configuration**: Configurable cross-origin policies
- ✅ **Rate Limiting**: Built-in request rate limiting support
- ⚠️ **HTTPS Required**: Always use HTTPS in production
- ⚠️ **Secret Key Security**: Never commit SECRET_KEY to version control
- ⚠️ **Dependency Updates**: Regularly update dependencies for security patches

## 🌍 Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MONGODB_URL` | MongoDB connection string | Yes | - |
| `DATABASE_NAME` | Database name | Yes | `b2c_auth_db` |
| `SECRET_KEY` | JWT secret key (32+ characters) | Yes | - |
| `ALGORITHM` | JWT algorithm | No | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiration time | No | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiration time | No | `7` |
| `AWS_REGION` | AWS service region | No | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key | No | - |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | No | - |
| `COGNITO_USER_POOL_ID` | AWS Cognito user pool ID | No | - |
| `COGNITO_CLIENT_ID` | AWS Cognito client ID | No | - |
| `COGNITO_CLIENT_SECRET` | AWS Cognito client secret | No | - |
| `DYNAMODB_TABLE_PREFIX` | DynamoDB table prefix | No | `b2c_auth_` |
| `AWS_SES_REGION` | AWS SES region for emails | No | `us-west-2` |
| `DEBUG` | Debug mode | No | `True` |
| `ENVIRONMENT` | Environment name | No | `staging` |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) | No | `http://localhost:3000,http://localhost:8000` |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For issues and questions, please open an issue on the GitHub repository or contact the development team.

## 👥 Authors

- Your Name / Your Organization

---

**Note**: This API is designed for B2C applications and provides a complete authentication solution. Make sure to configure all security settings appropriately for your production environment.