import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status
from app.core.config import settings

class DynamoDBService:
    def __init__(self):
        self.region = settings.aws_region
        self.table_prefix = settings.dynamodb_table_prefix
        
        # Initialize DynamoDB client
        self.client = boto3.client(
            'dynamodb',
            region_name=self.region,
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key or None
        )
        
        # Initialize DynamoDB resource
        self.dynamodb = boto3.resource(
            'dynamodb',
            region_name=self.region,
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key or None
        )
        
        # Initialize table references
        self.users_table = None
        self.sessions_table = None
        self.initialize_tables()
    
    def initialize_tables(self):
        """Initialize table references and create tables if they don't exist"""
        self.users_table = self.get_or_create_table(
            f"{self.table_prefix}users",
            [
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            [
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'  # String
                }
            ]
        )
        
        self.sessions_table = self.get_or_create_table(
            f"{self.table_prefix}sessions",
            [
                {
                    'AttributeName': 'session_id',
                    'KeyType': 'HASH'  # Partition key
                },
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'RANGE'  # Sort key
                }
            ],
            [
                {
                    'AttributeName': 'session_id',
                    'AttributeType': 'S'  # String
                },
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'  # String
                }
            ]
        )
    
    def get_or_create_table(self, table_name: str, key_schema: List[Dict], attribute_definitions: List[Dict]):
        """Get a reference to a DynamoDB table, creating it if it doesn't exist"""
        try:
            # Try to get the table
            table = self.dynamodb.Table(table_name)
            table.load()  # Will raise an exception if the table doesn't exist
            return table
        except self.client.exceptions.ResourceNotFoundException:
            # Table doesn't exist, create it
            if settings.environment == 'production':
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Table {table_name} does not exist in production environment"
                )
            
            # Create the table
            self.client.create_table(
                TableName=table_name,
                KeySchema=key_schema,
                AttributeDefinitions=attribute_definitions,
                BillingMode='PAY_PER_REQUEST'  # On-demand capacity
            )
            
            # Wait for the table to be created
            waiter = self.client.get_waiter('table_exists')
            waiter.wait(TableName=table_name)
            
            return self.dynamodb.Table(table_name)
    
    # User operations
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user in DynamoDB"""
        try:
            response = self.users_table.put_item(
                Item=user_data,
                ConditionExpression='attribute_not_exists(user_id)'
            )
            return user_data
        except self.client.exceptions.ConditionalCheckFailedException:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this ID already exists"
            )
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a user by ID"""
        response = self.users_table.get_item(Key={'user_id': user_id})
        return response.get('Item')
    
    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a user's information"""
        update_expression = 'SET ' + ', '.join(f'#{k} = :{k}' for k in update_data.keys())
        expression_attribute_names = {f'#{k}': k for k in update_data.keys()}
        expression_attribute_values = {f':{k}': v for k, v in update_data.items()}
        
        try:
            response = self.users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues='ALL_NEW'
            )
            return response.get('Attributes', {})
        except self.client.exceptions.ResourceNotFoundException:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    
    # Session operations
    async def create_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new session"""
        try:
            self.sessions_table.put_item(Item=session_data)
            return session_data
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create session: {str(e)}"
            )
    
    async def get_session(self, session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a session by ID and user ID"""
        response = self.sessions_table.get_item(
            Key={
                'session_id': session_id,
                'user_id': user_id
            }
        )
        return response.get('Item')
    
    async def delete_session(self, session_id: str, user_id: str) -> bool:
        """Delete a session"""
        try:
            self.sessions_table.delete_item(
                Key={
                    'session_id': session_id,
                    'user_id': user_id
                }
            )
            return True
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete session: {str(e)}"
            )

# Create a singleton instance
dynamodb_service = DynamoDBService()
