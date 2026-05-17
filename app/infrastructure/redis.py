"""
Enterprise Redis infrastructure for Mary V5
Supports distributed rate limiting, session management, and caching
"""

import os
import asyncio
from typing import Optional, Any
import redis.asyncio as redis

# Global Redis client
_redis_client: Optional[redis.Redis] = None


async def get_redis_client() -> redis.Redis:
    """Get Redis client instance"""
    global _redis_client
    if _redis_client is None:
        await init_redis()
    return _redis_client


async def init_redis():
    """Initialize Redis connection with enterprise configuration"""
    global _redis_client
    
    try:
        # Redis configuration from environment
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        redis_password = os.getenv("REDIS_PASSWORD")
        redis_db = int(os.getenv("REDIS_DB", "0"))
        redis_max_connections = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
        
        # Create Redis client with enterprise settings
        _redis_client = redis.from_url(
            redis_url,
            password=redis_password,
            db=redis_db,
            max_connections=redis_max_connections,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        
        # Test connection
        await _redis_client.ping()
        print(f"[INFO] Redis conectado exitosamente: {redis_url}")
        return True
        
    except Exception as exc:
        print(f"[ERROR] Error conectando a Redis: {str(exc)}")
        _redis_client = None
        return False


async def close_redis():
    """Close Redis connection gracefully"""
    global _redis_client
    
    if _redis_client:
        try:
            await _redis_client.close()
            print("[INFO] Conexión Redis cerrada correctamente")
        except Exception as exc:
            print(f"[ERROR] Error cerrando Redis: {str(exc)}")
        finally:
            _redis_client = None


class RedisManager:
    """Enterprise Redis manager for distributed operations"""
    
    def __init__(self):
        self.client = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.client = await get_redis_client()
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        # Client is managed globally, no cleanup needed here
        pass


# Rate limiting specific Redis operations
async def add_rate_limit_request(key: str, window_seconds: int) -> int:
    """Add request to rate limit window and return current count"""
    client = await get_redis_client()
    if not client:
        return 0
    
    current_time = int(asyncio.get_event_loop().time())
    window_start = current_time - window_seconds
    
    # Use Redis sorted set for sliding window
    pipeline = client.pipeline()
    
    # Remove old entries
    pipeline.zremrangebyscore(key, 0, window_start)
    
    # Add current request
    pipeline.zadd(key, {str(current_time): current_time})
    
    # Count current requests
    pipeline.zcard(key)
    
    # Set expiration
    pipeline.expire(key, window_seconds)
    
    results = await pipeline.execute()
    return results[2]  # zcard result


async def get_rate_limit_info(key: str) -> dict:
    """Get rate limit information for a key"""
    client = await get_redis_client()
    if not client:
        return {"count": 0, "ttl": 0}
    
    try:
        count = await client.zcard(key)
        ttl = await client.ttl(key)
        return {"count": count, "ttl": ttl}
    except Exception:
        return {"count": 0, "ttl": 0}


# Session management operations
async def set_session(session_id: str, data: dict, expire_seconds: int = 3600):
    """Store session data in Redis"""
    client = await get_redis_client()
    if not client:
        return False
    
    try:
        import json
        await client.setex(
            f"session:{session_id}",
            expire_seconds,
            json.dumps(data)
        )
        return True
    except Exception as e:
        print(f"[ERROR] Error setting session: {e}")
        return False


async def get_session(session_id: str) -> Optional[dict]:
    """Get session data from Redis"""
    client = await get_redis_client()
    if not client:
        return None
    
    try:
        import json
        data = await client.get(f"session:{session_id}")
        return json.loads(data) if data else None
    except Exception:
        return None


async def delete_session(session_id: str) -> bool:
    """Delete session from Redis"""
    client = await get_redis_client()
    if not client:
        return False
    
    try:
        await client.delete(f"session:{session_id}")
        return True
    except Exception:
        return False


# Cache operations
async def cache_set(key: str, value: Any, expire_seconds: int = 3600) -> bool:
    """Set cache value with expiration"""
    client = await get_redis_client()
    if not client:
        return False
    
    try:
        import json
        serialized_value = json.dumps(value) if not isinstance(value, str) else value
        await client.setex(key, expire_seconds, serialized_value)
        return True
    except Exception:
        return False


async def cache_get(key: str) -> Optional[Any]:
    """Get cache value"""
    client = await get_redis_client()
    if not client:
        return None
    
    try:
        import json
        value = await client.get(key)
        if value is None:
            return None
        
        # Try to deserialize as JSON
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    except Exception:
        return None


async def cache_delete(key: str) -> bool:
    """Delete cache key"""
    client = await get_redis_client()
    if not client:
        return False
    
    try:
        await client.delete(key)
        return True
    except Exception:
        return False
