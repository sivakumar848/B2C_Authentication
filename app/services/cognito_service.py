import boto3
from botocore.exceptions import ClientError
from fastapi import HTTPException, status
from typing import Optional, Dict, Any
import os
from datetime import datetime, timedelta
import jwt
from jose import jws
from jose.exceptions import JWTError

class CognitoService:
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
        self.client_id = os.getenv('COGNITO_CLIENT_ID')
        self.client_secret = os.getenv('COGNITO_CLIENT_SECRET', None)
        self.client = boto3.client('cognito-idp', region_name=self.region)
        
        # JWT configuration
        self.jwt_secret = os.getenv('JWT_SECRET_KEY')
        self.jwt_algorithm = os.getenv('JWT_ALGORITHM', 'HS256')
        self.jwt_expire_minutes = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', 30))

    def sign_up(self, username: str, password: str, user_attributes: Dict[str, str]) -> Dict[str, Any]:
        """Register a new user with AWS Cognito"""
        try:
            signup_kwargs = {
                'ClientId': self.client_id,
                'Username': username,
                'Password': password,
                'UserAttributes': [
                    {'Name': k, 'Value': v} for k, v in user_attributes.items()
                    if k != 'email'  # email is passed as Username
                ]
            }
            
            if self.client_secret:
                signup_kwargs['SecretHash'] = self._get_secret_hash(username)
                
            response = self.client.sign_up(**signup_kwargs)
            return {
                'user_id': response['UserSub'],
                'is_confirmed': response['UserConfirmed']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UsernameExistsException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Username already exists'
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    def confirm_sign_up(self, username: str, confirmation_code: str) -> bool:
        """Confirm user registration with verification code"""
        try:
            confirm_kwargs = {
                'ClientId': self.client_id,
                'Username': username,
                'ConfirmationCode': confirmation_code
            }
            
            if self.client_secret:
                confirm_kwargs['SecretHash'] = self._get_secret_hash(username)
                
            self.client.confirm_sign_up(**confirm_kwargs)
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'CodeMismatchException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Invalid verification code'
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    def sign_in(self, username: str, password: str) -> Dict[str, str]:
        """Authenticate user and return tokens"""
        try:
            auth_kwargs = {
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'ClientId': self.client_id,
                'AuthParameters': {
                    'USERNAME': username,
                    'PASSWORD': password
                }
            }
            
            if self.client_secret:
                auth_kwargs['AuthParameters']['SECRET_HASH'] = self._get_secret_hash(username)
                
            response = self.client.initiate_auth(**auth_kwargs)
            return {
                'access_token': response['AuthenticationResult']['AccessToken'],
                'refresh_token': response['AuthenticationResult']['RefreshToken'],
                'id_token': response['AuthenticationResult']['IdToken'],
                'expires_in': response['AuthenticationResult']['ExpiresIn']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Incorrect username or password'
                )
            if error_code == 'UserNotConfirmedException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='User is not confirmed. Please check your email for verification code.'
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    def refresh_token(self, refresh_token: str, username: str) -> Dict[str, str]:
        """Refresh access token using refresh token"""
        try:
            auth_kwargs = {
                'AuthFlow': 'REFRESH_TOKEN_AUTH',
                'ClientId': self.client_id,
                'AuthParameters': {
                    'REFRESH_TOKEN': refresh_token
                }
            }
            
            if self.client_secret:
                auth_kwargs['AuthParameters']['SECRET_HASH'] = self._get_secret_hash(username)
                
            response = self.client.initiate_auth(**auth_kwargs)
            return {
                'access_token': response['AuthenticationResult']['AccessToken'],
                'id_token': response['AuthenticationResult']['IdToken'],
                'expires_in': response['AuthenticationResult']['ExpiresIn']
            }
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid refresh token'
            )

    def forgot_password(self, username: str) -> bool:
        """Initiate forgot password flow"""
        try:
            forgot_pw_kwargs = {
                'ClientId': self.client_id,
                'Username': username
            }
            
            if self.client_secret:
                forgot_pw_kwargs['SecretHash'] = self._get_secret_hash(username)
                
            self.client.forgot_password(**forgot_pw_kwargs)
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UserNotFoundException':
                # For security reasons, don't reveal if user exists or not
                return True
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    def confirm_forgot_password(self, username: str, confirmation_code: str, new_password: str) -> bool:
        """Confirm new password with verification code"""
        try:
            confirm_pw_kwargs = {
                'ClientId': self.client_id,
                'Username': username,
                'ConfirmationCode': confirmation_code,
                'Password': new_password
            }
            
            if self.client_secret:
                confirm_pw_kwargs['SecretHash'] = self._get_secret_hash(username)
                
            self.client.confirm_forgot_password(**confirm_pw_kwargs)
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'CodeMismatchException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Invalid verification code'
                )
            if error_code == 'ExpiredCodeException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Verification code has expired. Please request a new one.'
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    def get_user(self, access_token: str) -> Dict[str, Any]:
        """Get user details using access token"""
        try:
            response = self.client.get_user(AccessToken=access_token)
            return {
                'username': response['Username'],
                'user_attributes': {
                    attr['Name']: attr['Value']
                    for attr in response['UserAttributes']
                },
                'enabled': response.get('Enabled', True),
                'user_status': response.get('UserStatus')
            }
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid access token'
            )

    def _get_secret_hash(self, username: str) -> str:
        """Generate secret hash for Cognito"""
        if not self.client_secret:
            return None
            
        message = username + self.client_id
        dig = hmac.new(
            key=self.client_secret.encode('UTF-8'),
            msg=message.encode('UTF-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()

    def create_jwt_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT token for additional app-specific authentication"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.jwt_expire_minutes)
            
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.jwt_secret, algorithm=self.jwt_algorithm)

    def verify_jwt_token(self, token: str) -> dict:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
                options={"verify_signature": True}
            )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

# Create a singleton instance
cognito_service = CognitoService()
