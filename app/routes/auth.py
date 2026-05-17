from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta

from app.schemas.auth import LoginRequest, LoginResponse, UserResponse
from app.core.jwt_handler import jwt_handler, authenticate_user, get_user_by_username
from app.core.observability import track_authentication_event
from app.core.centralized_logging import log_audit_event, log_security_event
from app.middleware.defensive_monitoring import record_auth_failure
from app.core.rate_limit_config import limiter, AUTH_LIMIT

router = APIRouter()
security = HTTPBearer()


@router.post("/login", response_model=LoginResponse)
@limiter.limit(AUTH_LIMIT)
async def login(login_data: LoginRequest, request: Request):
    """Authenticate user and return JWT token"""
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        # Record authentication failure for defensive monitoring and observability
        await record_auth_failure(request, login_data.username)
        
        # Centralized logging
        log_audit_event(
            "login_failed",
            user=login_data.username,
            resource=f"ip:{request.client.host if request.client else 'unknown'}",
            result="failed",
            details={"ip": request.client.host if request.client else "unknown"}
        )
        
        await track_authentication_event(
            event_type="login_failed",
            username=login_data.username,
            source_ip=request.client.host if request.client else "unknown",
            success=False
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Record successful authentication
    log_audit_event(
        "login_success",
        user=login_data.username,
        resource=f"ip:{request.client.host if request.client else 'unknown'}",
        result="success",
        details={"ip": request.client.host if request.client else "unknown"}
    )
    
    await track_authentication_event(
        event_type="login_success",
        username=login_data.username,
        source_ip=request.client.host if request.client else "unknown",
        success=True
    )
    
    access_token_expires = timedelta(minutes=30)
    access_token = jwt_handler.create_access_token(
        data={"sub": user["username"], "user_id": user["id"]},
        expires_delta=access_token_expires
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=1800
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user information"""
    payload = jwt_handler.verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # In production, fetch from database
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
