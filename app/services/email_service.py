import os
import boto3
from botocore.exceptions import ClientError
from fastapi import HTTPException, status
from typing import Optional, Dict, Any, List, Union
from app.core.config import settings

class EmailService:
    def __init__(self):
        self.region = settings.ses_region
        self.sender = settings.ses_sender_email
        
        # Initialize SES client
        self.client = boto3.client(
            'ses',
            region_name=self.region,
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key or None
        )
    
    async def send_email(
        self,
        to_addresses: Union[str, List[str]],
        subject: str,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        cc_addresses: Optional[Union[str, List[str]]] = None,
        bcc_addresses: Optional[Union[str, List[str]]] = None,
        reply_to_addresses: Optional[Union[str, List[str]]] = None,
        configuration_set_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send an email using Amazon SES
        
        Args:
            to_addresses: Email address(es) of the recipient(s)
            subject: Email subject
            body_text: Email body in plain text
            body_html: Email body in HTML (optional)
            cc_addresses: CC recipient(s) (optional)
            bcc_addresses: BCC recipient(s) (optional)
            reply_to_addresses: Reply-to address(es) (optional)
            configuration_set_name: Configuration set to use (optional)
            
        Returns:
            dict: Response from SES API
        """
        if not body_text and not body_html:
            raise ValueError("Either body_text or body_html must be provided")
        
        # Convert single string to list if needed
        if isinstance(to_addresses, str):
            to_addresses = [to_addresses]
        if cc_addresses and isinstance(cc_addresses, str):
            cc_addresses = [cc_addresses]
        if bcc_addresses and isinstance(bcc_addresses, str):
            bcc_addresses = [bcc_addresses]
        if reply_to_addresses and isinstance(reply_to_addresses, str):
            reply_to_addresses = [reply_to_addresses]
        
        # Prepare message
        message = {'Subject': {'Data': subject}}
        
        # Add text body if provided
        if body_text:
            message['Body'] = {'Text': {'Data': body_text, 'Charset': 'UTF-8'}}
        
        # Add HTML body if provided (overwrites text body if both are provided)
        if body_html:
            if 'Body' not in message:
                message['Body'] = {}
            message['Body']['Html'] = {'Data': body_html, 'Charset': 'UTF-8'}
        
        # Prepare destination
        destination = {'ToAddresses': to_addresses}
        if cc_addresses:
            destination['CcAddresses'] = cc_addresses
        if bcc_addresses:
            destination['BccAddresses'] = bcc_addresses
        
        # Prepare reply-to addresses
        reply_tos = reply_to_addresses if reply_to_addresses else []
        
        # Send email
        try:
            response = self.client.send_email(
                Source=self.sender,
                Destination=destination,
                Message=message,
                ReplyToAddresses=reply_tos,
                ConfigurationSetName=configuration_set_name
            )
            return response
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'MessageRejected':
                detail = f"Email not sent. {error_message}"
            elif error_code == 'ConfigurationSetDoesNotExist':
                detail = f"The specified configuration set does not exist: {configuration_set_name}"
            else:
                detail = f"Failed to send email: {error_message}"
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=detail
            )
    
    async def send_verification_email(self, to_address: str, verification_url: str, user_name: str = "User"):
        """Send an email verification link to the user"""
        subject = "Verify Your Email Address"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verify Your Email</title>
        </head>
        <body>
            <h2>Welcome to Our Service, {user_name}!</h2>
            <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
            <p>
                <a href="{verification_url}" style="
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                ">Verify Email</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p><a href="{verification_url}">{verification_url}</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
        </body>
        </html>
        """
        
        text_content = f"""
        Welcome to Our Service, {user_name}!
        
        Thank you for registering. Please verify your email address by visiting this URL:
        
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, you can safely ignore this email.
        """.format(user_name=user_name, verification_url=verification_url)
        
        return await self.send_email(
            to_addresses=to_address,
            subject=subject,
            body_text=text_content,
            body_html=html_content
        )
    
    async def send_password_reset_email(self, to_address: str, reset_url: str, user_name: str = "User"):
        """Send a password reset link to the user"""
        subject = "Password Reset Request"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reset Your Password</title>
        </head>
        <body>
            <h2>Hello {user_name},</h2>
            <p>We received a request to reset your password. Click the button below to set a new password:</p>
            <p>
                <a href="{reset_url}" style="
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                ">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p><a href="{reset_url}">{reset_url}</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
        </body>
        </html>
        """
        
        text_content = f"""
        Hello {user_name},
        
        We received a request to reset your password. Please visit the following link to set a new password:
        
        {reset_url}
        
        This link will expire in 1 hour.
        
        If you didn't request a password reset, you can safely ignore this email.
        """.format(user_name=user_name, reset_url=reset_url)
        
        return await self.send_email(
            to_addresses=to_address,
            subject=subject,
            body_text=text_content,
            body_html=html_content
        )

# Create a singleton instance
email_service = EmailService()
