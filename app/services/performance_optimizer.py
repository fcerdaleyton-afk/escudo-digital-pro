"""
Performance Optimization Service for Mary V5 Enterprise
Async operations, caching, background workers, and memory optimization
"""

import os
import asyncio
import time
import json
import threading
from typing import Dict, List, Optional, Any, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
from functools import wraps, lru_cache
import redis.asyncio as redis
import psutil
import gc

from app.core.dependencies import logger
from app.core.centralized_logging import log_audit_event


@dataclass
class CacheEntry:
    """Cache entry with expiration"""
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: Optional[datetime] = None


class AdvancedCache:
    """Advanced caching system with multiple strategies"""
    
    def __init__(self):
        self.enabled = os.getenv("ADVANCED_CACHE_ENABLED", "true").lower() == "true"
        
        # Cache configuration
        self.default_ttl = int(os.getenv("CACHE_DEFAULT_TTL", "300"))  # 5 minutes
        self.max_cache_size = int(os.getenv("MAX_CACHE_SIZE", "10000"))
        self.cleanup_interval = int(os.getenv("CACHE_CLEANUP_INTERVAL", "60"))  # 1 minute
        
        # Cache storage
        self.memory_cache = {}
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_requests": 0
        }
        
        # Redis cache
        self.redis_client = None
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        
        # Cache strategies
        self.cache_strategies = {
            "lru": self._lru_eviction,
            "lfu": self._lfu_eviction,
            "ttl": self._ttl_eviction
        }
        
        self.active_strategy = os.getenv("CACHE_STRATEGY", "lru")
        
        logger.info("Advanced cache initialized", enabled=self.enabled)
    
    async def initialize(self):
        """Initialize cache components"""
        if not self.enabled:
            return
        
        try:
            # Initialize Redis
            self.redis_client = await redis.from_url(self.redis_url)
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_entries())
            
            logger.info("Cache initialized successfully")
            
        except Exception as e:
            logger.error("Cache initialization failed", error=str(e))
    
    async def get(self, key: str, use_redis: bool = True) -> Optional[Any]:
        """Get value from cache"""
        if not self.enabled:
            return None
        
        self.cache_stats["total_requests"] += 1
        
        # Try memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            
            # Check expiration
            if entry.expires_at and datetime.utcnow() > entry.expires_at:
                del self.memory_cache[key]
                self.cache_stats["misses"] += 1
                return None
            
            # Update access stats
            entry.access_count += 1
            entry.last_accessed = datetime.utcnow()
            self.cache_stats["hits"] += 1
            
            return entry.value
        
        # Try Redis cache
        if use_redis and self.redis_client:
            try:
                cached_value = await self.redis_client.get(key)
                if cached_value:
                    # Deserialize and store in memory cache
                    value = json.loads(cached_value)
                    await self.set(key, value, use_redis=False)
                    self.cache_stats["hits"] += 1
                    return value
            except Exception as e:
                logger.error("Redis cache get error", error=str(e))
        
        self.cache_stats["misses"] += 1
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None, 
                 use_redis: bool = True) -> bool:
        """Set value in cache"""
        if not self.enabled:
            return False
        
        # Check cache size limit
        if len(self.memory_cache) >= self.max_cache_size:
            await self._evict_entries()
        
        # Create cache entry
        expires_at = None
        if ttl:
            expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        elif self.default_ttl:
            expires_at = datetime.utcnow() + timedelta(seconds=self.default_ttl)
        
        entry = CacheEntry(
            value=value,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_accessed=datetime.utcnow()
        )
        
        # Store in memory cache
        self.memory_cache[key] = entry
        
        # Store in Redis cache
        if use_redis and self.redis_client:
            try:
                serialized_value = json.dumps(value, default=str)
                redis_ttl = ttl or self.default_ttl
                await self.redis_client.setex(key, redis_ttl, serialized_value)
            except Exception as e:
                logger.error("Redis cache set error", error=str(e))
        
        return True
    
    async def delete(self, key: str, use_redis: bool = True) -> bool:
        """Delete value from cache"""
        if not self.enabled:
            return False
        
        # Delete from memory cache
        deleted = key in self.memory_cache
        if deleted:
            del self.memory_cache[key]
        
        # Delete from Redis cache
        if use_redis and self.redis_client:
            try:
                await self.redis_client.delete(key)
                deleted = True
            except Exception as e:
                logger.error("Redis cache delete error", error=str(e))
        
        return deleted
    
    async def clear(self, pattern: str = "*", use_redis: bool = True):
        """Clear cache entries"""
        if not self.enabled:
            return
        
        # Clear memory cache
        if pattern == "*":
            self.memory_cache.clear()
        else:
            import re
            compiled_pattern = re.compile(pattern)
            keys_to_delete = [k for k in self.memory_cache.keys() if compiled_pattern.match(k)]
            for key in keys_to_delete:
                del self.memory_cache[key]
        
        # Clear Redis cache
        if use_redis and self.redis_client:
            try:
                if pattern == "*":
                    await self.redis_client.flushdb()
                else:
                    keys = await self.redis_client.keys(pattern)
                    if keys:
                        await self.redis_client.delete(*keys)
            except Exception as e:
                logger.error("Redis cache clear error", error=str(e))
    
    async def _evict_entries(self):
        """Evict cache entries based on strategy"""
        if self.active_strategy in self.cache_strategies:
            await self.cache_strategies[self.active_strategy]()
    
    async def _lru_eviction(self):
        """Least Recently Used eviction"""
        if len(self.memory_cache) == 0:
            return
        
        # Find least recently used entry
        lru_key = min(
            self.memory_cache.keys(),
            key=lambda k: self.memory_cache[k].last_accessed or datetime.min
        )
        
        del self.memory_cache[lru_key]
        self.cache_stats["evictions"] += 1
    
    async def _lfu_eviction(self):
        """Least Frequently Used eviction"""
        if len(self.memory_cache) == 0:
            return
        
        # Find least frequently used entry
        lfu_key = min(
            self.memory_cache.keys(),
            key=lambda k: self.memory_cache[k].access_count
        )
        
        del self.memory_cache[lfu_key]
        self.cache_stats["evictions"] += 1
    
    async def _ttl_eviction(self):
        """Time-to-Live eviction"""
        current_time = datetime.utcnow()
        expired_keys = []
        
        for key, entry in self.memory_cache.items():
            if entry.expires_at and current_time > entry.expires_at:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.memory_cache[key]
            self.cache_stats["evictions"] += 1
    
    async def _cleanup_expired_entries(self):
        """Background cleanup task"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._ttl_eviction()
                
                # Log cache stats
                hit_rate = (
                    self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100
                    if self.cache_stats["total_requests"] > 0 else 0
                )
                
                logger.debug(
                    "Cache statistics",
                    hit_rate=f"{hit_rate:.2f}%",
                    cache_size=len(self.memory_cache),
                    hits=self.cache_stats["hits"],
                    misses=self.cache_stats["misses"]
                )
                
            except Exception as e:
                logger.error("Cache cleanup error", error=str(e))
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = (
            self.cache_stats["hits"] / self.cache_stats["total_requests"] * 100
            if self.cache_stats["total_requests"] > 0 else 0
        )
        
        return {
            "enabled": self.enabled,
            "cache_size": len(self.memory_cache),
            "max_cache_size": self.max_cache_size,
            "hit_rate": hit_rate,
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "evictions": self.cache_stats["evictions"],
            "strategy": self.active_strategy
        }


class BackgroundWorker:
    """Background task worker"""
    
    def __init__(self):
        self.enabled = os.getenv("BACKGROUND_WORKER_ENABLED", "true").lower() == "true"
        
        # Worker configuration
        self.max_workers = int(os.getenv("MAX_WORKERS", "10"))
        self.queue_size = int(os.getenv("QUEUE_SIZE", "1000"))
        
        # Task queue
        self.task_queue = asyncio.Queue(maxsize=self.queue_size)
        self.workers = []
        self.running = False
        
        # Task statistics
        self.task_stats = {
            "completed": 0,
            "failed": 0,
            "queued": 0
        }
        
        logger.info("Background worker initialized", enabled=self.enabled)
    
    async def start(self):
        """Start background workers"""
        if not self.enabled or self.running:
            return
        
        self.running = True
        
        # Start worker tasks
        for i in range(self.max_workers):
            worker_task = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker_task)
        
        logger.info(f"Started {self.max_workers} background workers")
    
    async def stop(self):
        """Stop background workers"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel workers
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        self.workers.clear()
        logger.info("Background workers stopped")
    
    async def submit_task(self, task_func: Callable, *args, **kwargs) -> bool:
        """Submit task to background worker"""
        if not self.enabled:
            return False
        
        try:
            task = {
                "func": task_func,
                "args": args,
                "kwargs": kwargs,
                "submitted_at": datetime.utcnow()
            }
            
            await self.task_queue.put(task)
            self.task_stats["queued"] += 1
            
            return True
            
        except asyncio.QueueFull:
            logger.warning("Task queue is full")
            return False
    
    async def _worker(self, worker_name: str):
        """Background worker coroutine"""
        logger.info(f"{worker_name} started")
        
        while self.running:
            try:
                # Get task from queue
                task = await asyncio.wait_for(
                    self.task_queue.get(),
                    timeout=1.0
                )
                
                # Execute task
                try:
                    start_time = time.time()
                    
                    if asyncio.iscoroutinefunction(task["func"]):
                        await task["func"](*task["args"], **task["kwargs"])
                    else:
                        task["func"](*task["args"], **task["kwargs"])
                    
                    duration = time.time() - start_time
                    
                    self.task_stats["completed"] += 1
                    
                    logger.debug(
                        f"{worker_name} completed task",
                        duration=f"{duration:.3f}s"
                    )
                
                except Exception as e:
                    self.task_stats["failed"] += 1
                    logger.error(
                        f"{worker_name} task failed",
                        error=str(e),
                        task=task["func"].__name__
                    )
                
                finally:
                    self.task_queue.task_done()
            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"{worker_name} error", error=str(e))
        
        logger.info(f"{worker_name} stopped")
    
    def get_worker_stats(self) -> Dict[str, Any]:
        """Get worker statistics"""
        return {
            "enabled": self.enabled,
            "running": self.running,
            "max_workers": self.max_workers,
            "active_workers": len(self.workers),
            "queue_size": self.task_queue.qsize(),
            "max_queue_size": self.queue_size,
            "completed": self.task_stats["completed"],
            "failed": self.task_stats["failed"],
            "queued": self.task_stats["queued"]
        }


class MemoryOptimizer:
    """Memory optimization and monitoring"""
    
    def __init__(self):
        self.enabled = os.getenv("MEMORY_OPTIMIZER_ENABLED", "true").lower() == "true"
        
        # Optimization settings
        self.gc_threshold = float(os.getenv("GC_THRESHOLD", "0.8"))  # 80% memory usage
        self.optimization_interval = int(os.getenv("OPTIMIZATION_INTERVAL", "300"))  # 5 minutes
        
        # Memory tracking
        self.memory_history = deque(maxlen=100)
        self.optimization_stats = {
            "gc_runs": 0,
            "memory_freed": 0,
            "optimizations": 0
        }
        
        logger.info("Memory optimizer initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start memory monitoring"""
        if not self.enabled:
            return
        
        while True:
            try:
                await asyncio.sleep(self.optimization_interval)
                await self._optimize_memory()
                
            except Exception as e:
                logger.error("Memory optimization error", error=str(e))
    
    async def _optimize_memory(self):
        """Perform memory optimization"""
        # Get current memory usage
        memory_info = psutil.virtual_memory()
        memory_percent = memory_info.percent / 100
        
        # Store in history
        self.memory_history.append({
            "timestamp": datetime.utcnow(),
            "memory_percent": memory_percent,
            "available_gb": memory_info.available / (1024**3),
            "used_gb": memory_info.used / (1024**3)
        })
        
        # Check if optimization is needed
        if memory_percent > self.gc_threshold:
            await self._run_garbage_collection()
    
    async def _run_garbage_collection(self):
        """Run garbage collection"""
        try:
            # Get memory before GC
            memory_before = psutil.virtual_memory().used
            
            # Run garbage collection
            collected = gc.collect()
            
            # Get memory after GC
            memory_after = psutil.virtual_memory().used
            memory_freed = memory_before - memory_after
            
            self.optimization_stats["gc_runs"] += 1
            self.optimization_stats["memory_freed"] += memory_freed
            self.optimization_stats["optimizations"] += 1
            
            logger.info(
                "Garbage collection completed",
                objects_collected=collected,
                memory_freed=f"{memory_freed / (1024**2):.1f}MB"
            )
            
            log_audit_event(
                "memory_optimization",
                resource="system_memory",
                result="success",
                details={
                    "objects_collected": collected,
                    "memory_freed_mb": memory_freed / (1024**2)
                }
            )
        
        except Exception as e:
            logger.error("Garbage collection error", error=str(e))
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        current_memory = psutil.virtual_memory()
        
        return {
            "enabled": self.enabled,
            "current_memory_percent": current_memory.percent,
            "available_gb": current_memory.available / (1024**3),
            "used_gb": current_memory.used / (1024**3),
            "gc_threshold": self.gc_threshold * 100,
            "optimization_stats": self.optimization_stats,
            "memory_history_size": len(self.memory_history)
        }


class PerformanceOptimizer:
    """Main performance optimization service"""
    
    def __init__(self):
        self.enabled = os.getenv("PERFORMANCE_OPTIMIZER_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.cache = AdvancedCache()
        self.background_worker = BackgroundWorker()
        self.memory_optimizer = MemoryOptimizer()
        
        # Performance metrics
        self.performance_metrics = {
            "response_times": deque(maxlen=1000),
            "request_counts": defaultdict(int),
            "error_rates": defaultdict(float)
        }
        
        logger.info("Performance optimizer initialized", enabled=self.enabled)
    
    async def initialize(self):
        """Initialize all components"""
        if not self.enabled:
            return
        
        await self.cache.initialize()
        await self.background_worker.start()
        
        # Start memory monitoring
        asyncio.create_task(self.memory_optimizer.start_monitoring())
        
        logger.info("Performance optimizer initialized successfully")
    
    async def shutdown(self):
        """Shutdown all components"""
        await self.background_worker.stop()
        logger.info("Performance optimizer shutdown")
    
    def cache_result(self, ttl: Optional[int] = None, key_prefix: str = ""):
        """Decorator for caching function results"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.enabled:
                    return await func(*args, **kwargs)
                
                # Generate cache key
                cache_key = f"{key_prefix}:{func.__name__}:{hash(str(args) + str(kwargs))}"
                
                # Try to get from cache
                cached_result = await self.cache.get(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Cache result
                await self.cache.set(cache_key, result, ttl)
                
                return result
            
            return wrapper
        return decorator
    
    def run_background(self, priority: str = "normal"):
        """Decorator for running functions in background"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.enabled:
                    return await func(*args, **kwargs)
                
                # Submit to background worker
                success = await self.background_worker.submit_task(func, *args, **kwargs)
                
                if not success:
                    # Fallback to synchronous execution
                    return await func(*args, **kwargs)
                
                return None  # Background task doesn't return immediate result
            
            return wrapper
        return decorator
    
    async def track_performance(self, operation: str, duration: float, success: bool = True):
        """Track performance metrics"""
        if not self.enabled:
            return
        
        # Track response time
        self.performance_metrics["response_times"].append({
            "operation": operation,
            "duration": duration,
            "timestamp": datetime.utcnow(),
            "success": success
        })
        
        # Update request count
        self.performance_metrics["request_counts"][operation] += 1
        
        # Update error rate
        if not success:
            current_rate = self.performance_metrics["error_rates"][operation]
            total_requests = self.performance_metrics["request_counts"][operation]
            self.performance_metrics["error_rates"][operation] = (
                (current_rate * (total_requests - 1) + 1) / total_requests
            )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.enabled:
            return {"enabled": False}
        
        # Calculate average response times
        response_times = list(self.performance_metrics["response_times"])
        if response_times:
            avg_duration = sum(r["duration"] for r in response_times) / len(response_times)
            max_duration = max(r["duration"] for r in response_times)
            min_duration = min(r["duration"] for r in response_times)
        else:
            avg_duration = max_duration = min_duration = 0
        
        return {
            "enabled": True,
            "cache": self.cache.get_cache_stats(),
            "background_worker": self.background_worker.get_worker_stats(),
            "memory_optimizer": self.memory_optimizer.get_memory_stats(),
            "performance_metrics": {
                "total_requests": sum(self.performance_metrics["request_counts"].values()),
                "average_response_time": avg_duration,
                "max_response_time": max_duration,
                "min_response_time": min_duration,
                "operations": dict(self.performance_metrics["request_counts"]),
                "error_rates": dict(self.performance_metrics["error_rates"])
            }
        }


# Global performance optimizer
performance_optimizer = PerformanceOptimizer()


async def initialize_performance_optimizer():
    """Initialize performance optimizer"""
    await performance_optimizer.initialize()


async def shutdown_performance_optimizer():
    """Shutdown performance optimizer"""
    await performance_optimizer.shutdown()


def cache_result(ttl: Optional[int] = None, key_prefix: str = ""):
    """Cache result decorator"""
    return performance_optimizer.cache_result(ttl, key_prefix)


def run_background(priority: str = "normal"):
    """Background task decorator"""
    return performance_optimizer.run_background(priority)


async def track_performance(operation: str, duration: float, success: bool = True):
    """Track performance metrics"""
    await performance_optimizer.track_performance(operation, duration, success)


def get_performance_summary() -> Dict[str, Any]:
    """Get performance summary"""
    return performance_optimizer.get_performance_summary()
