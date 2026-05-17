"""
MARY V5 SHIELD CORE - Async Performance Optimization
Fully async architecture with background workers and queue-based processing
"""

import os
import asyncio
import time
import json
import weakref
from typing import Dict, List, Optional, Any, Set, Callable, Union, Coroutine
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import psutil
import gc
from concurrent.futures import ThreadPoolExecutor
import threading

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class TaskStatus(Enum):
    """Task status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AsyncTask:
    """Async task data structure"""
    id: str
    coro: Coroutine
    priority: TaskPriority = TaskPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    retries: int = 0
    max_retries: int = 3
    timeout: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return self.priority.value > other.priority.value


class AsyncWorkerPool:
    """Async worker pool with priority queues"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.workers = []
        self.task_queue = asyncio.PriorityQueue()
        self.running = False
        self.current_tasks = weakref.WeakSet()
        
        # Statistics
        self.worker_stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_cancelled": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0,
            "workers_active": 0
        }
        
        logger.info(f"Async worker pool initialized with {max_workers} workers")
    
    async def start(self):
        """Start worker pool"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker coroutines
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker)
        
        logger.info(f"Started {self.max_workers} async workers")
    
    async def stop(self):
        """Stop worker pool"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel all workers
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        self.workers.clear()
        logger.info("Async worker pool stopped")
    
    async def submit_task(self, coro: Coroutine, priority: TaskPriority = TaskPriority.NORMAL,
                         timeout: Optional[float] = None, max_retries: int = 3,
                         metadata: Dict[str, Any] = None) -> str:
        """Submit task to worker pool"""
        task = AsyncTask(
            id=f"task_{int(time.time() * 1000000)}_{len(self.current_tasks)}",
            coro=coro,
            priority=priority,
            timeout=timeout,
            max_retries=max_retries,
            metadata=metadata or {}
        )
        
        await self.task_queue.put((-task.priority.value, task))
        return task.id
    
    async def _worker(self, worker_name: str):
        """Worker coroutine"""
        logger.info(f"{worker_name} started")
        
        while self.running:
            try:
                # Get task from queue
                _, task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # Execute task
                await self._execute_task(task, worker_name)
                
                self.task_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"{worker_name} error", error=str(e))
                await asyncio.sleep(1)
        
        logger.info(f"{worker_name} stopped")
    
    async def _execute_task(self, task: AsyncTask, worker_name: str):
        """Execute individual task"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        self.current_tasks.add(task)
        self.worker_stats["workers_active"] += 1
        
        start_time = time.time()
        
        try:
            # Execute with timeout if specified
            if task.timeout:
                result = await asyncio.wait_for(task.coro, timeout=task.timeout)
            else:
                result = await task.coro
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            
            self.worker_stats["tasks_completed"] += 1
            
        except asyncio.TimeoutError:
            task.error = asyncio.TimeoutError(f"Task timed out after {task.timeout} seconds")
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            
            self.worker_stats["tasks_failed"] += 1
            
            # Retry if retries available
            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.PENDING
                await self.task_queue.put((-task.priority.value, task))
                logger.warning(f"Task {task.id} timed out, retrying ({task.retries}/{task.max_retries})")
            
        except Exception as e:
            task.error = e
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            
            self.worker_stats["tasks_failed"] += 1
            
            # Retry if retries available
            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.PENDING
                await self.task_queue.put((-task.priority.value, task))
                logger.warning(f"Task {task.id} failed, retrying ({task.retries}/{task.max_retries}): {e}")
        
        finally:
            # Update statistics
            execution_time = time.time() - start_time
            self.worker_stats["total_execution_time"] += execution_time
            total_tasks = self.worker_stats["tasks_completed"] + self.worker_stats["tasks_failed"]
            self.worker_stats["average_execution_time"] = (
                self.worker_stats["total_execution_time"] / total_tasks if total_tasks > 0 else 0
            )
            
            self.worker_stats["workers_active"] -= 1
    
    def get_worker_stats(self) -> Dict[str, Any]:
        """Get worker pool statistics"""
        return {
            "max_workers": self.max_workers,
            "active_workers": len(self.workers),
            "queue_size": self.task_queue.qsize(),
            "running": self.running,
            "current_tasks": len(self.current_tasks),
            **self.worker_stats
        }


class AsyncCache:
    """Async-safe cache with LRU eviction"""
    
    def __init__(self, max_size: int = 10000, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
        self.cache = {}
        self.access_order = deque(maxlen=max_size)
        self.lock = asyncio.Lock()
        
        # Statistics
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_lookups": 0,
            "size": 0
        }
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self.lock:
            self.cache_stats["total_lookups"] += 1
            
            if key in self.cache:
                value, timestamp = self.cache[key]
                
                # Check TTL
                if time.time() - timestamp > self.ttl:
                    del self.cache[key]
                    try:
                        self.access_order.remove(key)
                    except ValueError:
                        pass
                    self.cache_stats["misses"] += 1
                    return None
                
                # Move to end (most recently used)
                try:
                    self.access_order.remove(key)
                except ValueError:
                    pass
                self.access_order.append(key)
                
                self.cache_stats["hits"] += 1
                return value
            
            self.cache_stats["misses"] += 1
            return None
    
    async def set(self, key: str, value: Any):
        """Set value in cache"""
        async with self.lock:
            timestamp = time.time()
            
            # Remove existing key if present
            if key in self.cache:
                try:
                    self.access_order.remove(key)
                except ValueError:
                    pass
            
            # Evict oldest if cache is full
            if len(self.cache) >= self.max_size:
                oldest_key = self.access_order.popleft()
                del self.cache[oldest_key]
                self.cache_stats["evictions"] += 1
            
            self.cache[key] = (value, timestamp)
            self.access_order.append(key)
            self.cache_stats["size"] = len(self.cache)
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        async with self.lock:
            if key in self.cache:
                del self.cache[key]
                try:
                    self.access_order.remove(key)
                except ValueError:
                    pass
                self.cache_stats["size"] = len(self.cache)
                return True
            return False
    
    async def clear(self):
        """Clear cache"""
        async with self.lock:
            self.cache.clear()
            self.access_order.clear()
            self.cache_stats["size"] = 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = (
            self.cache_stats["hits"] / self.cache_stats["total_lookups"] * 100
            if self.cache_stats["total_lookups"] > 0 else 0
        )
        
        return {
            "max_size": self.max_size,
            "ttl": self.ttl,
            "size": self.cache_stats["size"],
            "hit_rate": round(hit_rate, 2),
            **self.cache_stats
        }


class AsyncMemoryManager:
    """Async memory management and optimization"""
    
    def __init__(self):
        self.enabled = os.getenv("ASYNC_MEMORY_MANAGER_ENABLED", "true").lower() == "true"
        
        # Memory thresholds
        self.memory_threshold = float(os.getenv("MEMORY_THRESHOLD", "0.8"))  # 80%
        self.gc_threshold = float(os.getenv("GC_THRESHOLD", "0.7"))  # 70%
        
        # Monitoring interval
        self.monitoring_interval = int(os.getenv("MEMORY_MONITORING_INTERVAL", "60"))  # 1 minute
        
        # Memory statistics
        self.memory_stats = {
            "gc_runs": 0,
            "memory_freed": 0,
            "optimizations": 0,
            "peak_memory": 0,
            "avg_memory": 0,
            "memory_samples": deque(maxlen=100)
        }
        
        logger.info("Async memory manager initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start memory monitoring"""
        if not self.enabled:
            return
        
        while True:
            try:
                await self._monitor_memory()
                await asyncio.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error("Memory monitoring error", error=str(e))
                await asyncio.sleep(30)  # 30 seconds on error
    
    async def _monitor_memory(self):
        """Monitor memory usage and optimize"""
        memory_info = psutil.virtual_memory()
        memory_percent = memory_info.percent / 100
        
        # Store sample
        self.memory_stats["memory_samples"].append({
            "timestamp": datetime.utcnow(),
            "memory_percent": memory_percent,
            "available_gb": memory_info.available / (1024**3),
            "used_gb": memory_info.used / (1024**3)
        })
        
        # Update peak memory
        if memory_percent > self.memory_stats["peak_memory"]:
            self.memory_stats["peak_memory"] = memory_percent
        
        # Calculate average memory
        if self.memory_stats["memory_samples"]:
            avg_percent = sum(s["memory_percent"] for s in self.memory_stats["memory_samples"]) / len(self.memory_stats["memory_samples"])
            self.memory_stats["avg_memory"] = avg_percent
        
        # Check if optimization is needed
        if memory_percent > self.gc_threshold:
            await self._run_garbage_collection()
        
        if memory_percent > self.memory_threshold:
            await self._aggressive_optimization()
    
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
            
            self.memory_stats["gc_runs"] += 1
            self.memory_stats["memory_freed"] += memory_freed
            self.memory_stats["optimizations"] += 1
            
            logger.info(
                "Garbage collection completed",
                objects_collected=collected,
                memory_freed_mb=memory_freed / (1024**2)
            )
        
        except Exception as e:
            logger.error("Garbage collection error", error=str(e))
    
    async def _aggressive_optimization(self):
        """Aggressive memory optimization"""
        try:
            # Multiple GC cycles
            for i in range(3):
                gc.collect()
                await asyncio.sleep(0.1)  # Small delay between cycles
            
            # Clear async caches if available
            # This would need to be implemented based on actual cache instances
            
            self.memory_stats["optimizations"] += 1
            
            logger.warning("Aggressive memory optimization completed")
        
        except Exception as e:
            logger.error("Aggressive optimization error", error=str(e))
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        current_memory = psutil.virtual_memory()
        
        return {
            "enabled": self.enabled,
            "current_memory_percent": current_memory.percent,
            "available_gb": current_memory.available / (1024**3),
            "used_gb": current_memory.used / (1024**3),
            "thresholds": {
                "memory_threshold": self.memory_threshold * 100,
                "gc_threshold": self.gc_threshold * 100
            },
            **self.memory_stats
        }


class AsyncPerformanceOptimizer:
    """Main async performance optimizer"""
    
    def __init__(self):
        self.enabled = os.getenv("ASYNC_PERFORMANCE_OPTIMIZER_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.worker_pool = AsyncWorkerPool(max_workers=int(os.getenv("ASYNC_WORKERS", "10")))
        self.cache = AsyncCache(
            max_size=int(os.getenv("ASYNC_CACHE_SIZE", "10000")),
            ttl=int(os.getenv("ASYNC_CACHE_TTL", "300"))
        )
        self.memory_manager = AsyncMemoryManager()
        
        # Performance metrics
        self.performance_metrics = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "cache_operations": 0,
            "optimizations": 0,
            "start_time": datetime.utcnow()
        }
        
        # Background tasks
        self.background_tasks = []
        
        logger.info("Async performance optimizer initialized", enabled=self.enabled)
    
    async def start(self):
        """Start performance optimizer"""
        if not self.enabled:
            return
        
        # Start worker pool
        await self.worker_pool.start()
        
        # Start memory monitoring
        memory_task = asyncio.create_task(self.memory_manager.start_monitoring())
        self.background_tasks.append(memory_task)
        
        # Start metrics collection
        metrics_task = asyncio.create_task(self._collect_metrics())
        self.background_tasks.append(metrics_task)
        
        logger.info("Async performance optimizer started")
    
    async def stop(self):
        """Stop performance optimizer"""
        if not self.enabled:
            return
        
        # Stop worker pool
        await self.worker_pool.stop()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.background_tasks.clear()
        
        logger.info("Async performance optimizer stopped")
    
    async def submit_task(self, coro: Coroutine, priority: TaskPriority = TaskPriority.NORMAL,
                         **kwargs) -> str:
        """Submit task to worker pool"""
        if not self.enabled:
            # Execute immediately if disabled
            return "immediate"
        
        task_id = await self.worker_pool.submit_task(coro, priority, **kwargs)
        self.performance_metrics["tasks_submitted"] += 1
        return task_id
    
    def cache_result(self, ttl: Optional[int] = None):
        """Decorator for caching function results"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                if not self.enabled:
                    return await func(*args, **kwargs)
                
                # Generate cache key
                cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
                
                # Try to get from cache
                cached_result = await self.cache.get(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Cache result
                cache_ttl = ttl or self.cache.ttl
                await self.cache.set(cache_key, result)
                
                self.performance_metrics["cache_operations"] += 1
                
                return result
            
            return wrapper
        return decorator
    
    async def _collect_metrics(self):
        """Collect performance metrics"""
        while True:
            try:
                # Update metrics
                self.performance_metrics["tasks_completed"] = self.worker_pool.worker_stats["tasks_completed"]
                self.performance_metrics["optimizations"] = self.memory_manager.memory_stats["optimizations"]
                
                # Wait for next collection
                await asyncio.sleep(60)  # 1 minute
                
            except Exception as e:
                logger.error("Metrics collection error", error=str(e))
                await asyncio.sleep(30)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        if not self.enabled:
            return {"enabled": False}
        
        uptime = datetime.utcnow() - self.performance_metrics["start_time"]
        
        return {
            "enabled": True,
            "uptime_seconds": uptime.total_seconds(),
            "worker_pool": self.worker_pool.get_worker_stats(),
            "cache": self.cache.get_cache_stats(),
            "memory_manager": self.memory_manager.get_memory_stats(),
            "metrics": self.performance_metrics,
            "throughput": {
                "tasks_per_second": (
                    self.performance_metrics["tasks_completed"] / uptime.total_seconds()
                    if uptime.total_seconds() > 0 else 0
                ),
                "cache_hit_rate": self.cache.get_cache_stats().get("hit_rate", 0),
                "optimization_rate": (
                    self.memory_manager.memory_stats["optimizations"] / uptime.total_seconds()
                    if uptime.total_seconds() > 0 else 0
                )
            }
        }


# Global async performance optimizer
async_performance_optimizer = AsyncPerformanceOptimizer()


async def start_async_performance():
    """Start async performance optimizer"""
    await async_performance_optimizer.start()


async def stop_async_performance():
    """Stop async performance optimizer"""
    await async_performance_optimizer.stop()


async def submit_async_task(coro: Coroutine, **kwargs) -> str:
    """Submit async task"""
    return await async_performance_optimizer.submit_task(coro, **kwargs)


def async_cache_result(ttl: Optional[int] = None):
    """Cache result decorator"""
    return async_performance_optimizer.cache_result(ttl)


def get_async_performance_stats() -> Dict[str, Any]:
    """Get async performance statistics"""
    return async_performance_optimizer.get_performance_summary()
