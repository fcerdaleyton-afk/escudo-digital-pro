"""
Authentication schemas for request/response validation
"""

from pydantic import BaseModel, EmailStr, Field, constr
from typing import Optional


class LoginRequest(BaseModel):
    """Login request schema with validation"""
    username: constr(min_length=3, max_length=50, strip_whitespace=True)
    password: constr(min_length=8, max_length=128, strip_whitespace=True)


class LoginResponse(BaseModel):
    """Login response schema"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    """User information response"""
    id: int
    username: str
    email: Optional[str] = None
    is_active: bool = True
