"""
MARY V5 SHIELD CORE - Security Cache System
IOC cache, IP reputation cache, threat cache, TTL support, and async-safe caching
"""

import os
import time
import json
import asyncio
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, OrderedDict
import weakref

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class CacheType(Enum):
    """Cache types"""
    IOC = "ioc"
    IP_REPUTATION = "ip_reputation"
    THREAT = "threat"
    SESSION = "session"
    RATE_LIMIT = "rate_limit"
    USER = "user"
    SYSTEM = "system"


class CacheEvictionPolicy(Enum):
    """Cache eviction policies"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live
    FIFO = "fifo"  # First In First Out


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    cache_type: CacheType
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    ttl: Optional[float] = None  # Time to live in seconds
    expires_at: Optional[datetime] = None
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization setup"""
        if self.ttl and not self.expires_at:
            self.expires_at = self.created_at + timedelta(seconds=self.ttl)
        
        # Calculate size
        self.size_bytes = len(json.dumps(self.value, default=str).encode('utf-8'))
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def access(self) -> Any:
        """Access the entry and update metadata"""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1
        return self.value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['cache_type'] = self.cache_type.value
        data['created_at'] = self.created_at.isoformat()
        data['last_accessed'] = self.last_accessed.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data


class IOCEntry:
    """IOC (Indicator of Compromise) cache entry"""
    
    def __init__(self, ioc_type: str, value: str, reputation: str = "unknown",
                 confidence: float = 0.5, source: str = "unknown", **kwargs):
        self.ioc_type = ioc_type
        self.value = value
        self.reputation = reputation
        self.confidence = confidence
        self.source = source
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.tags = kwargs.get("tags", [])
        self.context = kwargs.get("context", {})
        self.metadata = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "reputation": self.reputation,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tags": self.tags,
            "context": self.context,
            "metadata": self.metadata
        }


class ThreatEntry:
    """Threat cache entry"""
    
    def __init__(self, threat_type: str, severity: str, description: str,
                 source_ip: str = None, **kwargs):
        self.threat_type = threat_type
        self.severity = severity
        self.description = description
        self.source_ip = source_ip
        self.first_detected = datetime.utcnow()
        self.last_detected = datetime.utcnow()
        self.detection_count = 1
        self.mitigation_status = kwargs.get("mitigation_status", "none")
        self.indicators = kwargs.get("indicators", [])
        self.context = kwargs.get("context", {})
        self.metadata = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "first_detected": self.first_detected.isoformat(),
            "last_detected": self.last_detected.isoformat(),
            "detection_count": self.detection_count,
            "mitigation_status": self.mitigation_status,
            "indicators": self.indicators,
            "context": self.context,
            "metadata": self.metadata
        }


class AsyncCache:
    """Async-safe cache with configurable eviction policies"""
    
    def __init__(self, cache_type: CacheType, max_size: int = 10000, ttl: int = 3600,
                 eviction_policy: CacheEvictionPolicy = CacheEvictionPolicy.LRU):
        self.cache_type = cache_type
        self.max_size = max_size
        self.default_ttl = ttl
        self.eviction_policy = eviction_policy
        
        # Storage
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order = OrderedDict()  # For LRU
        self.frequency_order = defaultdict(int)  # For LFU
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_lookups": 0,
            "current_size": 0,
            "total_size_bytes": 0,
            "cache_type": cache_type.value
        }
        
        self.logger = get_structured_logger(f"async_cache.{cache_type.value}")
        
        # Background cleanup
        self.cleanup_task = None
        
        self.logger.info(f"Async cache initialized: {cache_type.value}", 
                        max_size=max_size, ttl=ttl, eviction_policy=eviction_policy.value)
    
    async def start(self):
        """Start cache background tasks"""
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self):
        """Stop cache background tasks"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self._lock:
            self.stats["total_lookups"] += 1
            
            entry = self.cache.get(key)
            if entry is None:
                self.stats["misses"] += 1
                return None
            
            # Check expiration
            if entry.is_expired():
                await self._remove_entry(key)
                self.stats["misses"] += 1
                return None
            
            # Access entry
            value = entry.access()
            
            # Update access order for LRU
            if self.eviction_policy == CacheEvictionPolicy.LRU:
                self.access_order.move_to_end(key)
            
            # Update frequency for LFU
            if self.eviction_policy == CacheEvictionPolicy.LFU:
                self.frequency_order[key] += 1
            
            self.stats["hits"] += 1
            return value
    
    async def set(self, key: str, value: Any, ttl: Optional[float] = None,
                  metadata: Dict[str, Any] = None) -> bool:
        """Set value in cache"""
        async with self._lock:
            # Calculate TTL
            effective_ttl = ttl if ttl is not None else self.default_ttl
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                cache_type=self.cache_type,
                ttl=effective_ttl,
                metadata=metadata or {}
            )
            
            # Check if we need to evict
            if len(self.cache) >= self.max_size and key not in self.cache:
                await self._evict_entries()
            
            # Remove existing entry if present
            if key in self.cache:
                await self._remove_entry(key)
            
            # Add new entry
            self.cache[key] = entry
            self.stats["current_size"] = len(self.cache)
            self.stats["total_size_bytes"] += entry.size_bytes
            
            # Update access order for LRU
            if self.eviction_policy == CacheEvictionPolicy.LRU:
                self.access_order[key] = None
                self.access_order.move_to_end(key)
            
            # Update frequency for LFU
            if self.eviction_policy == CacheEvictionPolicy.LFU:
                self.frequency_order[key] = 1
            
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete entry from cache"""
        async with self._lock:
            return await self._remove_entry(key)
    
    async def clear(self):
        """Clear all entries"""
        async with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.frequency_order.clear()
            self.stats["current_size"] = 0
            self.stats["total_size_bytes"] = 0
    
    async def _remove_entry(self, key: str) -> bool:
        """Remove entry from cache"""
        if key in self.cache:
            entry = self.cache[key]
            del self.cache[key]
            
            # Update access order
            self.access_order.pop(key, None)
            self.frequency_order.pop(key, None)
            
            # Update statistics
            self.stats["current_size"] = len(self.cache)
            self.stats["total_size_bytes"] -= entry.size_bytes
            
            return True
        return False
    
    async def _evict_entries(self):
        """Evict entries based on policy"""
        if not self.cache:
            return
        
        evict_count = max(1, self.max_size // 10)  # Evict 10% at most
        
        if self.eviction_policy == CacheEvictionPolicy.LRU:
            # Remove least recently used
            for _ in range(evict_count):
                if self.access_order:
                    key = next(iter(self.access_order))
                    await self._remove_entry(key)
                    self.stats["evictions"] += 1
        
        elif self.eviction_policy == CacheEvictionPolicy.LFU:
            # Remove least frequently used
            sorted_items = sorted(self.frequency_order.items(), key=lambda x: x[1])
            for key, _ in sorted_items[:evict_count]:
                await self._remove_entry(key)
                self.stats["evictions"] += 1
        
        elif self.eviction_policy == CacheEvictionPolicy.TTL:
            # Remove expired entries
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]
            for key in expired_keys:
                await self._remove_entry(key)
                self.stats["evictions"] += 1
        
        elif self.eviction_policy == CacheEvictionPolicy.FIFO:
            # Remove oldest entries
            keys_to_remove = list(self.cache.keys())[:evict_count]
            for key in keys_to_remove:
                await self._remove_entry(key)
                self.stats["evictions"] += 1
    
    async def _cleanup_loop(self):
        """Background cleanup loop"""
        while True:
            try:
                await asyncio.sleep(300)  # 5 minutes
                
                # Clean up expired entries
                expired_keys = [
                    key for key, entry in self.cache.items()
                    if entry.is_expired()
                ]
                
                for key in expired_keys:
                    await self._remove_entry(key)
                    self.stats["evictions"] += 1
                
                if expired_keys:
                    self.logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Cache cleanup error", error=str(e))
                await asyncio.sleep(60)  # 1 minute on error
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = (
            self.stats["hits"] / self.stats["total_lookups"] * 100
            if self.stats["total_lookups"] > 0 else 0
        )
        
        return {
            "cache_type": self.cache_type.value,
            "max_size": self.max_size,
            "current_size": self.stats["current_size"],
            "total_size_bytes": self.stats["total_size_bytes"],
            "hit_rate": round(hit_rate, 2),
            "eviction_policy": self.eviction_policy.value,
            **self.stats
        }


class SecurityCacheManager:
    """Main security cache manager"""
    
    def __init__(self):
        self.enabled = os.getenv("SECURITY_CACHE_MANAGER_ENABLED", "true").lower() == "true"
        
        # Cache configurations
        self.cache_configs = self._load_cache_configs()
        
        # Initialize caches
        self.caches: Dict[CacheType, AsyncCache] = {}
        for cache_type, config in self.cache_configs.items():
            self.caches[cache_type] = AsyncCache(
                cache_type=cache_type,
                max_size=config["max_size"],
                ttl=config["ttl"],
                eviction_policy=CacheEvictionPolicy(config["eviction_policy"])
            )
        
        # Global statistics
        self.global_stats = {
            "total_hits": 0,
            "total_misses": 0,
            "total_evictions": 0,
            "total_size_bytes": 0,
            "cache_count": len(self.caches),
            "start_time": datetime.utcnow()
        }
        
        # Background tasks
        self.monitoring_task = None
        
        self.logger = get_structured_logger("security_cache_manager")
        
        # Start caches
        if self.enabled:
            asyncio.create_task(self.start())
        
        self.logger.info("Security cache manager initialized", enabled=self.enabled)
    
    def _load_cache_configs(self) -> Dict[CacheType, Dict[str, Any]]:
        """Load cache configurations"""
        return {
            CacheType.IOC: {
                "max_size": int(os.getenv("IOC_CACHE_SIZE", "50000")),
                "ttl": int(os.getenv("IOC_CACHE_TTL", "3600")),  # 1 hour
                "eviction_policy": os.getenv("IOC_CACHE_EVICTION", "lru")
            },
            CacheType.IP_REPUTATION: {
                "max_size": int(os.getenv("IP_REPUTATION_CACHE_SIZE", "100000")),
                "ttl": int(os.getenv("IP_REPUTATION_CACHE_TTL", "1800")),  # 30 minutes
                "eviction_policy": os.getenv("IP_REPUTATION_CACHE_EVICTION", "lru")
            },
            CacheType.THREAT: {
                "max_size": int(os.getenv("THREAT_CACHE_SIZE", "25000")),
                "ttl": int(os.getenv("THREAT_CACHE_TTL", "7200")),  # 2 hours
                "eviction_policy": os.getenv("THREAT_CACHE_EVICTION", "lfu")
            },
            CacheType.SESSION: {
                "max_size": int(os.getenv("SESSION_CACHE_SIZE", "10000")),
                "ttl": int(os.getenv("SESSION_CACHE_TTL", "1800")),  # 30 minutes
                "eviction_policy": os.getenv("SESSION_CACHE_EVICTION", "ttl")
            },
            CacheType.RATE_LIMIT: {
                "max_size": int(os.getenv("RATE_LIMIT_CACHE_SIZE", "50000")),
                "ttl": int(os.getenv("RATE_LIMIT_CACHE_TTL", "300")),  # 5 minutes
                "eviction_policy": os.getenv("RATE_LIMIT_CACHE_EVICTION", "fifo")
            },
            CacheType.USER: {
                "max_size": int(os.getenv("USER_CACHE_SIZE", "20000")),
                "ttl": int(os.getenv("USER_CACHE_TTL", "3600")),  # 1 hour
                "eviction_policy": os.getenv("USER_CACHE_EVICTION", "lru")
            },
            CacheType.SYSTEM: {
                "max_size": int(os.getenv("SYSTEM_CACHE_SIZE", "5000")),
                "ttl": int(os.getenv("SYSTEM_CACHE_TTL", "600")),  # 10 minutes
                "eviction_policy": os.getenv("SYSTEM_CACHE_EVICTION", "lru")
            }
        }
    
    async def start(self):
        """Start cache manager"""
        if not self.enabled:
            return
        
        # Start all caches
        for cache in self.caches.values():
            await cache.start()
        
        # Start monitoring
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        self.logger.info("Security cache manager started")
    
    async def stop(self):
        """Stop cache manager"""
        if not self.enabled:
            return
        
        # Stop monitoring
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Stop all caches
        for cache in self.caches.values():
            await cache.stop()
        
        self.logger.info("Security cache manager stopped")
    
    async def get_ioc(self, ioc_type: str, value: str) -> Optional[IOCEntry]:
        """Get IOC from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.IOC]
        key = f"{ioc_type}:{value}"
        
        entry_data = await cache.get(key)
        if entry_data:
            return IOCEntry(**entry_data)
        
        return None
    
    async def set_ioc(self, ioc_type: str, value: str, reputation: str = "unknown",
                     confidence: float = 0.5, source: str = "unknown", **kwargs) -> bool:
        """Set IOC in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.IOC]
        key = f"{ioc_type}:{value}"
        
        ioc_entry = IOCEntry(
            ioc_type=ioc_type,
            value=value,
            reputation=reputation,
            confidence=confidence,
            source=source,
            **kwargs
        )
        
        return await cache.set(key, ioc_entry.to_dict())
    
    async def get_ip_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get IP reputation from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.IP_REPUTATION]
        return await cache.get(ip_address)
    
    async def set_ip_reputation(self, ip_address: str, reputation_data: Dict[str, Any],
                               ttl: Optional[float] = None) -> bool:
        """Set IP reputation in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.IP_REPUTATION]
        return await cache.set(ip_address, reputation_data, ttl)
    
    async def get_threat(self, threat_id: str) -> Optional[ThreatEntry]:
        """Get threat from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.THREAT]
        
        threat_data = await cache.get(threat_id)
        if threat_data:
            return ThreatEntry(**threat_data)
        
        return None
    
    async def set_threat(self, threat_id: str, threat_type: str, severity: str,
                         description: str, **kwargs) -> bool:
        """Set threat in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.THREAT]
        
        threat_entry = ThreatEntry(
            threat_type=threat_type,
            severity=severity,
            description=description,
            **kwargs
        )
        
        return await cache.set(threat_id, threat_entry.to_dict())
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.SESSION]
        return await cache.get(session_id)
    
    async def set_session(self, session_id: str, session_data: Dict[str, Any],
                         ttl: Optional[float] = None) -> bool:
        """Set session in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.SESSION]
        return await cache.set(session_id, session_data, ttl)
    
    async def get_rate_limit(self, key: str) -> Optional[Dict[str, Any]]:
        """Get rate limit data from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.RATE_LIMIT]
        return await cache.get(key)
    
    async def set_rate_limit(self, key: str, rate_data: Dict[str, Any],
                            ttl: Optional[float] = None) -> bool:
        """Set rate limit data in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.RATE_LIMIT]
        return await cache.set(key, rate_data, ttl)
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user data from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.USER]
        return await cache.get(user_id)
    
    async def set_user(self, user_id: str, user_data: Dict[str, Any],
                      ttl: Optional[float] = None) -> bool:
        """Set user data in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.USER]
        return await cache.set(user_id, user_data, ttl)
    
    async def get_system(self, key: str) -> Optional[Dict[str, Any]]:
        """Get system data from cache"""
        if not self.enabled:
            return None
        
        cache = self.caches[CacheType.SYSTEM]
        return await cache.get(key)
    
    async def set_system(self, key: str, system_data: Dict[str, Any],
                         ttl: Optional[float] = None) -> bool:
        """Set system data in cache"""
        if not self.enabled:
            return False
        
        cache = self.caches[CacheType.SYSTEM]
        return await cache.set(key, system_data, ttl)
    
    async def clear_cache(self, cache_type: Optional[CacheType] = None):
        """Clear cache(s)"""
        if not self.enabled:
            return
        
        if cache_type:
            await self.caches[cache_type].clear()
        else:
            for cache in self.caches.values():
                await cache.clear()
    
    async def _monitoring_loop(self):
        """Monitor cache performance"""
        while True:
            try:
                await asyncio.sleep(300)  # 5 minutes
                
                # Update global statistics
                total_hits = sum(cache.stats["hits"] for cache in self.caches.values())
                total_misses = sum(cache.stats["misses"] for cache in self.caches.values())
                total_evictions = sum(cache.stats["evictions"] for cache in self.caches.values())
                total_size_bytes = sum(cache.stats["total_size_bytes"] for cache in self.caches.values())
                
                self.global_stats.update({
                    "total_hits": total_hits,
                    "total_misses": total_misses,
                    "total_evictions": total_evictions,
                    "total_size_bytes": total_size_bytes
                })
                
                # Log performance metrics
                total_lookups = total_hits + total_misses
                hit_rate = (total_hits / total_lookups * 100) if total_lookups > 0 else 0
                
                self.logger.info(
                    "Cache performance",
                    hit_rate=round(hit_rate, 2),
                    total_size_mb=round(total_size_bytes / (1024 * 1024), 2),
                    total_evictions=total_evictions
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Cache monitoring error", error=str(e))
                await asyncio.sleep(60)  # 1 minute on error
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        uptime = datetime.utcnow() - self.global_stats["start_time"]
        
        cache_stats = {}
        for cache_type, cache in self.caches.items():
            cache_stats[cache_type.value] = cache.get_statistics()
        
        total_lookups = self.global_stats["total_hits"] + self.global_stats["total_misses"]
        hit_rate = (self.global_stats["total_hits"] / total_lookups * 100) if total_lookups > 0 else 0
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": uptime.total_seconds(),
            "global_stats": {
                **self.global_stats,
                "hit_rate": round(hit_rate, 2),
                "total_size_mb": round(self.global_stats["total_size_bytes"] / (1024 * 1024), 2)
            },
            "cache_stats": cache_stats,
            "cache_configs": {
                cache_type.value: config for cache_type, config in self.cache_configs.items()
            }
        }


# Global security cache manager
security_cache_manager = SecurityCacheManager()


async def start_security_cache():
    """Start security cache manager"""
    await security_cache_manager.start()


async def stop_security_cache():
    """Stop security cache manager"""
    await security_cache_manager.stop()


async def get_ioc_from_cache(ioc_type: str, value: str) -> Optional[IOCEntry]:
    """Get IOC from cache"""
    return await security_cache_manager.get_ioc(ioc_type, value)


async def set_ioc_in_cache(ioc_type: str, value: str, **kwargs) -> bool:
    """Set IOC in cache"""
    return await security_cache_manager.set_ioc(ioc_type, value, **kwargs)


async def get_ip_reputation_from_cache(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get IP reputation from cache"""
    return await security_cache_manager.get_ip_reputation(ip_address)


async def set_ip_reputation_in_cache(ip_address: str, reputation_data: Dict[str, Any], **kwargs) -> bool:
    """Set IP reputation in cache"""
    return await security_cache_manager.set_ip_reputation(ip_address, reputation_data, **kwargs)


async def get_threat_from_cache(threat_id: str) -> Optional[ThreatEntry]:
    """Get threat from cache"""
    return await security_cache_manager.get_threat(threat_id)


async def set_threat_in_cache(threat_id: str, **kwargs) -> bool:
    """Set threat in cache"""
    return await security_cache_manager.set_threat(threat_id, **kwargs)


def get_security_cache_statistics() -> Dict[str, Any]:
    """Get security cache statistics"""
    return security_cache_manager.get_statistics()
