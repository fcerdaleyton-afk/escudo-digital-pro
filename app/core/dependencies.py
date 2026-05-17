"""
Dependency injection container and core dependencies
"""

import logging
from typing import AsyncGenerator
from fastapi import Depends, Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings
from app.core.jwt_handler import jwt_handler, get_user_by_username
from app.schemas.auth import UserResponse


# Configure structured logging
class StructuredLogger:
    """Production-ready structured logger"""
    
    def __init__(self):
        self.logger = logging.getLogger("mary_v5")
        self.logger.setLevel(logging.INFO)
        
        # Console handler for development
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def info(self, message: str, **kwargs):
        """Log info message with optional context"""
        if kwargs:
            self.logger.info(f"{message} | {kwargs}")
        else:
            self.logger.info(message)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional context"""
        if kwargs:
            self.logger.warning(f"{message} | {kwargs}")
        else:
            self.logger.warning(message)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional context"""
        if kwargs:
            self.logger.error(f"{message} | {kwargs}")
        else:
            self.logger.error(message)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with optional context"""
        if kwargs:
            self.logger.critical(f"{message} | {kwargs}")
        else:
            self.logger.critical(message)


# Global logger instance
logger = StructuredLogger()


# Security dependency
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> UserResponse:
    """Dependency to get current authenticated user"""
    try:
        payload = jwt_handler.verify_token(credentials.credentials)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        return UserResponse(
            id=user["id"],
            username=user["username"],
            email=user.get("email"),
            is_active=user["is_active"]
        )
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_logger() -> StructuredLogger:
    """Dependency to get logger instance"""
    return logger


def get_settings() -> settings:
    """Dependency to get settings instance"""
    return settings
