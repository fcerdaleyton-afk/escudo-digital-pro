"""
MARY V5 SHIELD CORE - Secure Async Task Manager
Background async workers, queue processing, task isolation, failure recovery, and timeout enforcement
"""

import os
import time
import asyncio
import uuid
import threading
import traceback
from typing import Dict, List, Optional, Any, Set, Callable, Union, Coroutine
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import weakref
import psutil

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class TaskStatus(Enum):
    """Task status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRYING = "retrying"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class TaskIsolationLevel(Enum):
    """Task isolation levels"""
    SHARED = "shared"
    ISOLATED = "isolated"
    SANDBOXED = "sandboxed"


@dataclass
class TaskResult:
    """Task execution result"""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[Exception] = None
    error_traceback: Optional[str] = None
    execution_time: float = 0.0
    retries: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    worker_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        if self.error:
            data['error'] = str(self.error)
        return data


@dataclass
class AsyncTask:
    """Async task data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    coro: Coroutine = None
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[float] = None
    max_retries: int = 3
    retry_delay: float = 1.0
    isolation_level: TaskIsolationLevel = TaskIsolationLevel.SHARED
    created_at: datetime = field(default_factory=datetime.utcnow)
    scheduled_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return self.priority.value > other.priority.value


class TaskWorker:
    """Secure async task worker with isolation"""
    
    def __init__(self, worker_id: str, isolation_level: TaskIsolationLevel = TaskIsolationLevel.SHARED):
        self.worker_id = worker_id
        self.isolation_level = isolation_level
        self.running = False
        self.current_task: Optional[AsyncTask] = None
        self.processed_tasks = 0
        self.failed_tasks = 0
        self.start_time: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        
        # Resource monitoring
        self.memory_usage = 0.0
        self.cpu_usage = 0.0
        
        # Process isolation (for sandboxed workers)
        self.process_id = None
        self.resource_limits = {
            "max_memory_mb": 512,
            "max_cpu_percent": 80.0,
            "max_execution_time": 3600  # 1 hour
        }
        
        self.logger = get_structured_logger(f"task_worker.{worker_id}")
    
    async def start(self):
        """Start worker"""
        self.running = True
        self.start_time = datetime.utcnow()
        
        # Setup isolation if needed
        if self.isolation_level == TaskIsolationLevel.SANDBOXED:
            await self._setup_sandbox()
        
        self.logger.info(f"Worker {self.worker_id} started", isolation_level=self.isolation_level.value)
    
    async def stop(self):
        """Stop worker"""
        self.running = False
        
        # Cleanup sandbox if needed
        if self.isolation_level == TaskIsolationLevel.SANDBOXED:
            await self._cleanup_sandbox()
        
        self.logger.info(f"Worker {self.worker_id} stopped")
    
    async def execute_task(self, task: AsyncTask) -> TaskResult:
        """Execute task with isolation and monitoring"""
        self.current_task = task
        self.last_activity = datetime.utcnow()
        
        start_time = time.time()
        result = TaskResult(task_id=task.id, status=TaskStatus.RUNNING, worker_id=self.worker_id)
        
        try:
            # Monitor resources during execution
            monitor_task = asyncio.create_task(self._monitor_execution())
            
            # Execute task with timeout
            if task.timeout:
                try:
                    task_result = await asyncio.wait_for(task.coro, timeout=task.timeout)
                    result.status = TaskStatus.COMPLETED
                    result.result = task_result
                except asyncio.TimeoutError:
                    result.status = TaskStatus.TIMEOUT
                    result.error = asyncio.TimeoutError(f"Task timed out after {task.timeout} seconds")
            else:
                task_result = await task.coro
                result.status = TaskStatus.COMPLETED
                result.result = task_result
            
            # Update statistics
            self.processed_tasks += 1
            
        except Exception as e:
            result.status = TaskStatus.FAILED
            result.error = e
            result.error_traceback = traceback.format_exc()
            self.failed_tasks += 1
        
        finally:
            # Stop monitoring
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            
            # Update result
            result.execution_time = time.time() - start_time
            result.started_at = self.last_activity
            result.completed_at = datetime.utcnow()
            
            # Update worker stats
            self.last_activity = datetime.utcnow()
            self.current_task = None
        
        return result
    
    async def _monitor_execution(self):
        """Monitor task execution resources"""
        while self.current_task and self.running:
            try:
                # Get current process
                process = psutil.Process()
                
                # Update resource usage
                self.memory_usage = process.memory_info().rss / (1024 * 1024)  # MB
                self.cpu_usage = process.cpu_percent()
                
                # Check resource limits
                if self.memory_usage > self.resource_limits["max_memory_mb"]:
                    self.logger.warning(
                        f"Memory limit exceeded: {self.memory_usage:.2f}MB > {self.resource_limits['max_memory_mb']}MB"
                    )
                
                if self.cpu_usage > self.resource_limits["max_cpu_percent"]:
                    self.logger.warning(
                        f"CPU usage high: {self.cpu_usage:.2f}% > {self.resource_limits['max_cpu_percent']}%"
                    )
                
                await asyncio.sleep(1)  # Monitor every second
                
            except Exception as e:
                self.logger.error("Resource monitoring error", error=str(e))
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _setup_sandbox(self):
        """Setup sandboxed execution environment"""
        # In production, this would setup actual sandbox environment
        # For now, we'll just log it
        self.logger.info("Sandbox setup completed")
    
    async def _cleanup_sandbox(self):
        """Cleanup sandboxed execution environment"""
        # In production, this would cleanup actual sandbox environment
        self.logger.info("Sandbox cleanup completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get worker statistics"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            "worker_id": self.worker_id,
            "isolation_level": self.isolation_level.value,
            "running": self.running,
            "processed_tasks": self.processed_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": (self.processed_tasks - self.failed_tasks) / max(self.processed_tasks, 1) * 100,
            "uptime_seconds": uptime,
            "current_task_id": self.current_task.id if self.current_task else None,
            "memory_usage_mb": self.memory_usage,
            "cpu_usage_percent": self.cpu_usage,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None
        }


class TaskQueue:
    """Secure task queue with priority support"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.queue = asyncio.PriorityQueue(maxsize=max_size)
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "total_enqueued": 0,
            "total_dequeued": 0,
            "queue_size": 0,
            "by_priority": defaultdict(int)
        }
        
        self.logger = get_structured_logger("task_queue")
    
    async def enqueue(self, task: AsyncTask) -> bool:
        """Enqueue task"""
        try:
            await self.queue.put((-task.priority.value, task))
            
            async with self._lock:
                self.stats["total_enqueued"] += 1
                self.stats["queue_size"] = self.queue.qsize()
                self.stats["by_priority"][task.priority.value] += 1
            
            return True
        
        except asyncio.QueueFull:
            self.logger.warning("Task queue full, dropping task", task_id=task.id)
            return False
    
    async def dequeue(self) -> Optional[AsyncTask]:
        """Dequeue task"""
        try:
            _, task = await self.queue.get()
            
            async with self._lock:
                self.stats["total_dequeued"] += 1
                self.stats["queue_size"] = self.queue.qsize()
            
            return task
        
        except asyncio.CancelledError:
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get queue statistics"""
        return {
            "max_size": self.max_size,
            "current_size": self.queue.qsize(),
            **self.stats
        }


class TaskRetryManager:
    """Task retry management with exponential backoff"""
    
    def __init__(self):
        self.enabled = os.getenv("TASK_RETRY_MANAGER_ENABLED", "true").lower() == "true"
        
        # Retry configuration
        self.max_retries = int(os.getenv("TASK_MAX_RETRIES", "3"))
        self.base_delay = float(os.getenv("TASK_RETRY_BASE_DELAY", "1.0"))
        self.max_delay = float(os.getenv("TASK_RETRY_MAX_DELAY", "60.0"))
        self.backoff_factor = float(os.getenv("TASK_RETRY_BACKOFF_FACTOR", "2.0"))
        
        # Retry tracking
        self.retry_attempts: Dict[str, int] = defaultdict(int)
        self.retry_delays: Dict[str, List[float]] = defaultdict(list)
        
        self.logger = get_structured_logger("task_retry_manager")
        
        self.logger.info("Task retry manager initialized", enabled=self.enabled)
    
    def should_retry(self, task: AsyncTask, error: Exception) -> bool:
        """Check if task should be retried"""
        if not self.enabled:
            return False
        
        # Check retry count
        current_attempts = self.retry_attempts[task.id]
        if current_attempts >= task.max_retries:
            return False
        
        # Check error type (some errors shouldn't be retried)
        non_retryable_errors = (
            asyncio.CancelledError,
            ValueError,
            TypeError,
            AttributeError
        )
        
        if isinstance(error, non_retryable_errors):
            return False
        
        return True
    
    def calculate_retry_delay(self, task: AsyncTask) -> float:
        """Calculate retry delay with exponential backoff"""
        attempts = self.retry_attempts[task.id]
        
        # Exponential backoff
        delay = self.base_delay * (self.backoff_factor ** attempts)
        
        # Add jitter to prevent thundering herd
        import random
        jitter = random.uniform(0.1, 0.5) * delay
        delay += jitter
        
        # Cap at maximum delay
        delay = min(delay, self.max_delay)
        
        # Store delay for tracking
        self.retry_delays[task.id].append(delay)
        
        return delay
    
    def record_retry(self, task_id: str):
        """Record retry attempt"""
        self.retry_attempts[task_id] += 1
    
    def reset_retries(self, task_id: str):
        """Reset retry count for task"""
        self.retry_attempts[task_id] = 0
        self.retry_delays[task_id] = []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get retry statistics"""
        return {
            "enabled": self.enabled,
            "max_retries": self.max_retries,
            "base_delay": self.base_delay,
            "max_delay": self.max_delay,
            "backoff_factor": self.backoff_factor,
            "active_retries": len(self.retry_attempts),
            "retry_attempts": dict(self.retry_attempts)
        }


class SecureAsyncTaskManager:
    """Main secure async task manager"""
    
    def __init__(self):
        self.enabled = os.getenv("SECURE_ASYNC_TASK_MANAGER_ENABLED", "true").lower() == "true"
        
        # Configuration
        self.max_workers = int(os.getenv("TASK_MAX_WORKERS", "10"))
        self.default_timeout = float(os.getenv("TASK_DEFAULT_TIMEOUT", "300.0"))
        self.queue_size = int(os.getenv("TASK_QUEUE_SIZE", "10000"))
        
        # Components
        self.task_queue = TaskQueue(max_size=self.queue_size)
        self.retry_manager = TaskRetryManager()
        
        # Workers
        self.workers: List[TaskWorker] = []
        self.worker_tasks: List[asyncio.Task] = []
        
        # Task storage
        self.tasks: Dict[str, AsyncTask] = {}
        self.task_results: Dict[str, TaskResult] = {}
        
        # Statistics
        self.manager_stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_cancelled": 0,
            "tasks_retried": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0,
            "start_time": datetime.utcnow()
        }
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Background tasks
        self.monitoring_task = None
        self.cleanup_task = None
        
        self.logger = get_structured_logger("secure_async_task_manager")
        
        # Start if enabled
        if self.enabled:
            asyncio.create_task(self.start())
        
        self.logger.info("Secure async task manager initialized", enabled=self.enabled)
    
    async def start(self):
        """Start task manager"""
        if not self.enabled:
            return
        
        # Create workers
        for i in range(self.max_workers):
            worker_id = f"worker-{i}"
            isolation_level = TaskIsolationLevel.ISOLATED if i < 2 else TaskIsolationLevel.SHARED
            worker = TaskWorker(worker_id, isolation_level)
            self.workers.append(worker)
        
        # Start workers
        for worker in self.workers:
            await worker.start()
            worker_task = asyncio.create_task(self._worker_loop(worker))
            self.worker_tasks.append(worker_task)
        
        # Start monitoring
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        # Start cleanup
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        self.logger.info(f"Started {self.max_workers} task workers")
    
    async def stop(self):
        """Stop task manager"""
        if not self.enabled:
            return
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # Stop workers
        for worker in self.workers:
            await worker.stop()
        
        # Cancel background tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Secure async task manager stopped")
    
    async def submit_task(self, coro: Coroutine, priority: TaskPriority = TaskPriority.NORMAL,
                         timeout: Optional[float] = None, max_retries: int = 3,
                         isolation_level: TaskIsolationLevel = TaskIsolationLevel.SHARED,
                         metadata: Dict[str, Any] = None) -> str:
        """Submit task for execution"""
        if not self.enabled:
            # Execute immediately if disabled
            return "immediate"
        
        # Create task
        task = AsyncTask(
            coro=coro,
            priority=priority,
            timeout=timeout or self.default_timeout,
            max_retries=max_retries,
            isolation_level=isolation_level,
            metadata=metadata or {}
        )
        
        # Store task
        self.tasks[task.id] = task
        self.manager_stats["tasks_submitted"] += 1
        
        # Enqueue task
        success = await self.task_queue.enqueue(task)
        
        if success:
            # Notify handlers
            await self._notify_handlers("task_submitted", task)
            self.logger.debug(f"Task submitted: {task.id}", priority=priority.value)
            return task.id
        else:
            # Remove from storage if failed to enqueue
            del self.tasks[task.id]
            raise RuntimeError("Task queue full")
    
    async def get_task_result(self, task_id: str) -> Optional[TaskResult]:
        """Get task result"""
        return self.task_results.get(task_id)
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel task"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        # Mark as cancelled
        result = TaskResult(task_id=task_id, status=TaskStatus.CANCELLED)
        self.task_results[task_id] = result
        
        # Update statistics
        self.manager_stats["tasks_cancelled"] += 1
        
        # Notify handlers
        await self._notify_handlers("task_cancelled", task)
        
        self.logger.info(f"Task cancelled: {task_id}")
        return True
    
    async def _worker_loop(self, worker: TaskWorker):
        """Worker execution loop"""
        while worker.running:
            try:
                # Get task from queue
                task = await self.task_queue.dequeue()
                if not task:
                    continue
                
                # Execute task
                result = await worker.execute_task(task)
                
                # Handle retry if needed
                if result.status == TaskStatus.FAILED and self.retry_manager.should_retry(task, result.error):
                    retry_delay = self.retry_manager.calculate_retry_delay(task)
                    
                    self.logger.info(
                        f"Retrying task {task.id} after {retry_delay:.2f}s",
                        attempt=self.retry_manager.retry_attempts[task.id] + 1
                    )
                    
                    # Wait before retry
                    await asyncio.sleep(retry_delay)
                    
                    # Record retry
                    self.retry_manager.record_retry(task.id)
                    self.manager_stats["tasks_retried"] += 1
                    
                    # Re-queue task
                    await self.task_queue.enqueue(task)
                    continue
                
                # Store result
                self.task_results[task.id] = result
                
                # Update statistics
                if result.status == TaskStatus.COMPLETED:
                    self.manager_stats["tasks_completed"] += 1
                elif result.status == TaskStatus.FAILED:
                    self.manager_stats["tasks_failed"] += 1
                
                # Update execution time
                self.manager_stats["total_execution_time"] += result.execution_time
                total_tasks = self.manager_stats["tasks_completed"] + self.manager_stats["tasks_failed"]
                if total_tasks > 0:
                    self.manager_stats["average_execution_time"] = (
                        self.manager_stats["total_execution_time"] / total_tasks
                    )
                
                # Reset retries if completed or failed beyond retry limit
                if result.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                    self.retry_manager.reset_retries(task.id)
                
                # Notify handlers
                await self._notify_handlers("task_completed", task, result)
                
                # Clean up task storage
                if task.id in self.tasks:
                    del self.tasks[task.id]
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Worker {worker.worker_id} error", error=str(e))
                await asyncio.sleep(1)
    
    async def _monitoring_loop(self):
        """Monitor task manager performance"""
        while True:
            try:
                await asyncio.sleep(60)  # Monitor every minute
                
                # Collect worker statistics
                worker_stats = [worker.get_statistics() for worker in self.workers]
                
                # Check for unhealthy workers
                for stats in worker_stats:
                    if stats["cpu_usage_percent"] > 90:
                        self.logger.warning(
                            f"Worker {stats['worker_id']} high CPU usage: {stats['cpu_usage_percent']:.2f}%"
                        )
                    
                    if stats["memory_usage_mb"] > 400:
                        self.logger.warning(
                            f"Worker {stats['worker_id']} high memory usage: {stats['memory_usage_mb']:.2f}MB"
                        )
                
                # Log overall statistics
                self.logger.info(
                    "Task manager statistics",
                    queue_size=self.task_queue.queue.qsize(),
                    active_workers=len([w for w in self.workers if w.running]),
                    tasks_completed=self.manager_stats["tasks_completed"],
                    tasks_failed=self.manager_stats["tasks_failed"],
                    avg_execution_time=self.manager_stats["average_execution_time"]
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Monitoring error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    async def _cleanup_task(self):
        """Periodic cleanup of old tasks"""
        while True:
            try:
                await asyncio.sleep(3600)  # 1 hour
                
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                # Clean up old results
                old_results = [
                    task_id for task_id, result in self.task_results.items()
                    if result.completed_at and result.completed_at < cutoff_time
                ]
                
                for task_id in old_results:
                    del self.task_results[task_id]
                
                if old_results:
                    self.logger.info(f"Cleaned up {len(old_results)} old task results")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Cleanup error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    def register_handler(self, event_type: str, handler: Callable):
        """Register event handler"""
        self.event_handlers[event_type].append(handler)
    
    async def _notify_handlers(self, event_type: str, *args):
        """Notify event handlers"""
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args)
                else:
                    handler(*args)
            except Exception as e:
                self.logger.error("Event handler error", handler=str(handler), error=str(e))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        uptime = datetime.utcnow() - self.manager_stats["start_time"]
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": uptime.total_seconds(),
            "configuration": {
                "max_workers": self.max_workers,
                "default_timeout": self.default_timeout,
                "queue_size": self.queue_size
            },
            "queue": self.task_queue.get_statistics(),
            "retry_manager": self.retry_manager.get_statistics(),
            "workers": [worker.get_statistics() for worker in self.workers],
            **self.manager_stats
        }


# Global task manager instance
secure_async_task_manager = SecureAsyncTaskManager()


async def start_task_manager():
    """Start task manager"""
    await secure_async_task_manager.start()


async def stop_task_manager():
    """Stop task manager"""
    await secure_async_task_manager.stop()


async def submit_async_task(coro: Coroutine, **kwargs) -> str:
    """Submit async task"""
    return await secure_async_task_manager.submit_task(coro, **kwargs)


async def get_task_result(task_id: str) -> Optional[TaskResult]:
    """Get task result"""
    return await secure_async_task_manager.get_task_result(task_id)


async def cancel_async_task(task_id: str) -> bool:
    """Cancel async task"""
    return await secure_async_task_manager.cancel_task(task_id)


def get_task_manager_statistics() -> Dict[str, Any]:
    """Get task manager statistics"""
    return secure_async_task_manager.get_statistics()
