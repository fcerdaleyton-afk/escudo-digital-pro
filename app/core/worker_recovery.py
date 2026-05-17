#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Worker Recovery System
Automatic worker recovery with health monitoring and failover
"""

import os
import sys
import asyncio
import logging
import json
import time
import psutil
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/worker_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class WorkerStatus(Enum):
    """Worker status enumeration"""
    STARTING = "starting"
    RUNNING = "running"
    IDLE = "idle"
    BUSY = "busy"
    STALLED = "stalled"
    FAILED = "failed"
    RECOVERING = "recovering"
    STOPPED = "stopped"


class WorkerType(Enum):
    """Worker type enumeration"""
    TASK_PROCESSOR = "task_processor"
    WEBSOCKET_HANDLER = "websocket_handler"
    SECURITY_SCANNER = "security_scanner"
    THREAT_ANALYZER = "threat_analyzer"
    CACHE_MANAGER = "cache_manager"
    QUEUE_PROCESSOR = "queue_processor"


@dataclass
class WorkerMetrics:
    """Worker performance metrics"""
    worker_id: str
    worker_type: WorkerType
    status: WorkerStatus
    pid: int
    cpu_usage: float
    memory_usage: float
    tasks_processed: int
    tasks_failed: int
    average_processing_time: float
    last_activity: datetime
    start_time: datetime
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    stall_count: int = 0
    recovery_count: int = 0
    health_score: float = 1.0


@dataclass
class WorkerConfig:
    """Worker configuration"""
    worker_type: WorkerType
    max_tasks: int = 1000
    max_memory_mb: int = 512
    max_cpu_percent: float = 80.0
    stall_timeout: int = 300  # 5 minutes
    max_consecutive_failures: int = 5
    max_recovery_attempts: int = 3
    health_check_interval: int = 30  # seconds
    auto_restart: bool = True
    graceful_shutdown_timeout: int = 30  # seconds


class WorkerProcess:
    """Individual worker process management"""
    
    def __init__(self, worker_id: str, worker_type: WorkerType, config: WorkerConfig):
        self.worker_id = worker_id
        self.worker_type = worker_type
        self.config = config
        self.process: Optional[psutil.Process] = None
        self.task_queue = asyncio.Queue()
        self.status = WorkerStatus.STOPPED
        self.metrics = WorkerMetrics(
            worker_id=worker_id,
            worker_type=worker_type,
            status=WorkerStatus.STOPPED,
            pid=0,
            cpu_usage=0.0,
            memory_usage=0.0,
            tasks_processed=0,
            tasks_failed=0,
            average_processing_time=0.0,
            last_activity=datetime.utcnow(),
            start_time=datetime.utcnow()
        )
        self._shutdown_event = asyncio.Event()
        self._health_check_task: Optional[asyncio.Task] = None
        self._task_processor_task: Optional[asyncio.Task] = None
    
    async def start(self) -> bool:
        """Start the worker process"""
        try:
            logger.info(f"Starting worker {self.worker_id} of type {self.worker_type.value}")
            
            self.status = WorkerStatus.STARTING
            self.metrics.start_time = datetime.utcnow()
            
            # Create worker process
            self.process = await self._create_worker_process()
            
            if not self.process:
                self.status = WorkerStatus.FAILED
                return False
            
            self.metrics.pid = self.process.pid
            self.status = WorkerStatus.RUNNING
            
            # Start health monitoring
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            # Start task processor
            self._task_processor_task = asyncio.create_task(self._task_processor_loop())
            
            logger.info(f"Worker {self.worker_id} started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting worker {self.worker_id}: {e}")
            self.status = WorkerStatus.FAILED
            return False
    
    async def stop(self, graceful: bool = True) -> bool:
        """Stop the worker process"""
        try:
            logger.info(f"Stopping worker {self.worker_id}")
            
            self.status = WorkerStatus.STOPPED
            
            # Cancel tasks
            if self._health_check_task:
                self._health_check_task.cancel()
            if self._task_processor_task:
                self._task_processor_task.cancel()
            
            # Stop process
            if self.process:
                if graceful:
                    # Graceful shutdown
                    self._shutdown_event.set()
                    try:
                        await asyncio.wait_for(
                            self._wait_for_process_exit(),
                            timeout=self.config.graceful_shutdown_timeout
                        )
                    except asyncio.TimeoutError:
                        logger.warning(f"Worker {self.worker_id} did not shutdown gracefully, forcing")
                        self.process.kill()
                else:
                    # Forceful shutdown
                    self.process.kill()
                
                self.process = None
            
            logger.info(f"Worker {self.worker_id} stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping worker {self.worker_id}: {e}")
            return False
    
    async def restart(self) -> bool:
        """Restart the worker process"""
        try:
            logger.info(f"Restarting worker {self.worker_id}")
            
            # Stop worker
            await self.stop(graceful=True)
            
            # Update recovery count
            self.metrics.recovery_count += 1
            
            # Start worker
            success = await self.start()
            
            if success:
                logger.info(f"Worker {self.worker_id} restarted successfully")
            else:
                logger.error(f"Failed to restart worker {self.worker_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error restarting worker {self.worker_id}: {e}")
            return False
    
    async def _create_worker_process(self) -> Optional[psutil.Process]:
        """Create a new worker process"""
        try:
            # In a real implementation, this would create an actual process
            # For now, we'll simulate the process creation
            process_info = psutil.Process()
            process_info.pid = os.getpid()  # Use current PID for simulation
            
            return process_info
            
        except Exception as e:
            logger.error(f"Error creating worker process: {e}")
            return None
    
    async def _wait_for_process_exit(self):
        """Wait for process to exit"""
        try:
            if self.process:
                while self.process.is_running():
                    await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Error waiting for process exit: {e}")
    
    async def _health_check_loop(self):
        """Health check monitoring loop"""
        while not self._shutdown_event.is_set():
            try:
                await self._perform_health_check()
                await asyncio.sleep(self.config.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop for {self.worker_id}: {e}")
                await asyncio.sleep(5)  # Brief delay before retry
    
    async def _task_processor_loop(self):
        """Task processing loop"""
        while not self._shutdown_event.is_set():
            try:
                # Get next task
                task = await asyncio.wait_for(
                    self.task_queue.get(),
                    timeout=1.0
                )
                
                # Process task
                await self._process_task(task)
                
            except asyncio.TimeoutError:
                # No task available, continue
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in task processor loop for {self.worker_id}: {e}")
                await asyncio.sleep(1)  # Brief delay before retry
    
    async def _perform_health_check(self):
        """Perform health check on worker"""
        try:
            if not self.process:
                self.status = WorkerStatus.FAILED
                return
            
            # Check if process is running
            if not self.process.is_running():
                self.status = WorkerStatus.FAILED
                return
            
            # Update metrics
            await self._update_metrics()
            
            # Check for stall
            if self._is_stalled():
                self.status = WorkerStatus.STALLED
                self.metrics.stall_count += 1
                logger.warning(f"Worker {self.worker_id} is stalled")
                return
            
            # Check resource usage
            if self._exceeds_resource_limits():
                logger.warning(f"Worker {self.worker_id} exceeds resource limits")
                return
            
            # Update status
            if self.status == WorkerStatus.STARTING:
                self.status = WorkerStatus.RUNNING
            
            # Update health score
            self.metrics.health_score = self._calculate_health_score()
            
        except Exception as e:
            logger.error(f"Error performing health check for {self.worker_id}: {e}")
            self.status = WorkerStatus.FAILED
    
    async def _update_metrics(self):
        """Update worker metrics"""
        try:
            if not self.process:
                return
            
            # Get CPU and memory usage
            self.metrics.cpu_usage = self.process.cpu_percent()
            memory_info = self.process.memory_info()
            self.metrics.memory_usage = memory_info.rss / (1024 * 1024)  # MB
            
            # Update last activity
            self.metrics.last_activity = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating metrics for {self.worker_id}: {e}")
    
    def _is_stalled(self) -> bool:
        """Check if worker is stalled"""
        try:
            # Check if no recent activity
            time_since_activity = datetime.utcnow() - self.metrics.last_activity
            return time_since_activity.total_seconds() > self.config.stall_timeout
        except Exception as e:
            logger.error(f"Error checking stall status for {self.worker_id}: {e}")
            return False
    
    def _exceeds_resource_limits(self) -> bool:
        """Check if worker exceeds resource limits"""
        try:
            # Check CPU usage
            if self.metrics.cpu_usage > self.config.max_cpu_percent:
                return True
            
            # Check memory usage
            if self.metrics.memory_usage > self.config.max_memory_mb:
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking resource limits for {self.worker_id}: {e}")
            return False
    
    def _calculate_health_score(self) -> float:
        """Calculate worker health score"""
        try:
            score = 1.0
            
            # Penalize high CPU usage
            if self.metrics.cpu_usage > 50:
                score -= (self.metrics.cpu_usage - 50) * 0.01
            
            # Penalize high memory usage
            if self.metrics.memory_usage > 256:
                score -= (self.metrics.memory_usage - 256) * 0.001
            
            # Penalize consecutive failures
            if self.metrics.consecutive_failures > 0:
                score -= self.metrics.consecutive_failures * 0.1
            
            # Penalize stall count
            if self.metrics.stall_count > 0:
                score -= self.metrics.stall_count * 0.05
            
            # Ensure score is between 0 and 1
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating health score for {self.worker_id}: {e}")
            return 0.0
    
    async def _process_task(self, task: Dict[str, Any]):
        """Process a task"""
        try:
            start_time = time.time()
            
            # Update status
            self.status = WorkerStatus.BUSY
            self.metrics.last_activity = datetime.utcnow()
            
            # Process task based on worker type
            if self.worker_type == WorkerType.TASK_PROCESSOR:
                await self._process_general_task(task)
            elif self.worker_type == WorkerType.WEBSOCKET_HANDLER:
                await self._process_websocket_task(task)
            elif self.worker_type == WorkerType.SECURITY_SCANNER:
                await self._process_security_task(task)
            elif self.worker_type == WorkerType.THREAT_ANALYZER:
                await self._process_threat_task(task)
            elif self.worker_type == WorkerType.CACHE_MANAGER:
                await self._process_cache_task(task)
            elif self.worker_type == WorkerType.QUEUE_PROCESSOR:
                await self._process_queue_task(task)
            
            # Update metrics
            processing_time = time.time() - start_time
            self.metrics.tasks_processed += 1
            self.metrics.consecutive_successes += 1
            self.metrics.consecutive_failures = 0
            
            # Update average processing time
            total_tasks = self.metrics.tasks_processed
            self.metrics.average_processing_time = (
                (self.metrics.average_processing_time * (total_tasks - 1) + processing_time) / total_tasks
            )
            
            # Update status
            self.status = WorkerStatus.RUNNING
            
            logger.debug(f"Worker {self.worker_id} processed task in {processing_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Error processing task in worker {self.worker_id}: {e}")
            
            # Update metrics
            self.metrics.tasks_failed += 1
            self.metrics.consecutive_failures += 1
            self.metrics.consecutive_successes = 0
            
            # Update status
            self.status = WorkerStatus.RUNNING
    
    async def _process_general_task(self, task: Dict[str, Any]):
        """Process general task"""
        try:
            # Simulate task processing
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Error processing general task: {e}")
            raise
    
    async def _process_websocket_task(self, task: Dict[str, Any]):
        """Process WebSocket task"""
        try:
            # Simulate WebSocket task processing
            await asyncio.sleep(0.05)
        except Exception as e:
            logger.error(f"Error processing WebSocket task: {e}")
            raise
    
    async def _process_security_task(self, task: Dict[str, Any]):
        """Process security task"""
        try:
            # Simulate security task processing
            await asyncio.sleep(0.2)
        except Exception as e:
            logger.error(f"Error processing security task: {e}")
            raise
    
    async def _process_threat_task(self, task: Dict[str, Any]):
        """Process threat analysis task"""
        try:
            # Simulate threat analysis task processing
            await asyncio.sleep(0.3)
        except Exception as e:
            logger.error(f"Error processing threat task: {e}")
            raise
    
    async def _process_cache_task(self, task: Dict[str, Any]):
        """Process cache task"""
        try:
            # Simulate cache task processing
            await asyncio.sleep(0.05)
        except Exception as e:
            logger.error(f"Error processing cache task: {e}")
            raise
    
    async def _process_queue_task(self, task: Dict[str, Any]):
        """Process queue task"""
        try:
            # Simulate queue task processing
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Error processing queue task: {e}")
            raise
    
    async def add_task(self, task: Dict[str, Any]):
        """Add a task to the worker"""
        try:
            await self.task_queue.put(task)
        except Exception as e:
            logger.error(f"Error adding task to worker {self.worker_id}: {e}")
            raise
    
    def get_metrics(self) -> WorkerMetrics:
        """Get worker metrics"""
        return self.metrics


class WorkerRecoverySystem:
    """Worker recovery system with automatic failover"""
    
    def __init__(self):
        """Initialize worker recovery system"""
        self.workers: Dict[str, WorkerProcess] = {}
        self.worker_configs: Dict[WorkerType, WorkerConfig] = {}
        self.recovery_queue = asyncio.Queue()
        self.monitoring_task: Optional[asyncio.Task] = None
        self.recovery_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # Default configurations
        self._initialize_default_configs()
        
        # Recovery statistics
        self.recovery_stats = {
            'total_recoveries': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'auto_restarts': 0,
            'manual_restarts': 0
        }
        
        logger.info("Worker recovery system initialized")
    
    def _initialize_default_configs(self):
        """Initialize default worker configurations"""
        self.worker_configs = {
            WorkerType.TASK_PROCESSOR: WorkerConfig(
                worker_type=WorkerType.TASK_PROCESSOR,
                max_tasks=1000,
                max_memory_mb=512,
                max_cpu_percent=80.0,
                stall_timeout=300,
                max_consecutive_failures=5,
                max_recovery_attempts=3,
                health_check_interval=30,
                auto_restart=True
            ),
            WorkerType.WEBSOCKET_HANDLER: WorkerConfig(
                worker_type=WorkerType.WEBSOCKET_HANDLER,
                max_tasks=500,
                max_memory_mb=256,
                max_cpu_percent=70.0,
                stall_timeout=180,
                max_consecutive_failures=3,
                max_recovery_attempts=3,
                health_check_interval=15,
                auto_restart=True
            ),
            WorkerType.SECURITY_SCANNER: WorkerConfig(
                worker_type=WorkerType.SECURITY_SCANNER,
                max_tasks=200,
                max_memory_mb=1024,
                max_cpu_percent=90.0,
                stall_timeout=600,
                max_consecutive_failures=2,
                max_recovery_attempts=2,
                health_check_interval=60,
                auto_restart=True
            ),
            WorkerType.THREAT_ANALYZER: WorkerConfig(
                worker_type=WorkerType.THREAT_ANALYZER,
                max_tasks=100,
                max_memory_mb=2048,
                max_cpu_percent=95.0,
                stall_timeout=900,
                max_consecutive_failures=2,
                max_recovery_attempts=2,
                health_check_interval=120,
                auto_restart=True
            ),
            WorkerType.CACHE_MANAGER: WorkerConfig(
                worker_type=WorkerType.CACHE_MANAGER,
                max_tasks=1000,
                max_memory_mb=512,
                max_cpu_percent=60.0,
                stall_timeout=120,
                max_consecutive_failures=3,
                max_recovery_attempts=3,
                health_check_interval=30,
                auto_restart=True
            ),
            WorkerType.QUEUE_PROCESSOR: WorkerConfig(
                worker_type=WorkerType.QUEUE_PROCESSOR,
                max_tasks=2000,
                max_memory_mb=256,
                max_cpu_percent=70.0,
                stall_timeout=300,
                max_consecutive_failures=5,
                max_recovery_attempts=3,
                health_check_interval=30,
                auto_restart=True
            )
        }
    
    async def start(self):
        """Start the worker recovery system"""
        logger.info("Starting worker recovery system")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        # Start recovery task
        self.recovery_task = asyncio.create_task(self._recovery_loop())
        
        logger.info("Worker recovery system started")
    
    async def stop(self):
        """Stop the worker recovery system"""
        logger.info("Stopping worker recovery system")
        
        # Stop all workers
        await self.stop_all_workers()
        
        # Cancel tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
        if self.recovery_task:
            self.recovery_task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*[task for task in [self.monitoring_task, self.recovery_task] if task], return_exceptions=True)
        
        logger.info("Worker recovery system stopped")
    
    async def create_worker(self, worker_type: WorkerType, worker_id: Optional[str] = None) -> str:
        """Create a new worker"""
        try:
            if worker_id is None:
                worker_id = f"{worker_type.value}_{int(time.time())}"
            
            if worker_id in self.workers:
                raise ValueError(f"Worker {worker_id} already exists")
            
            config = self.worker_configs[worker_type]
            worker = WorkerProcess(worker_id, worker_type, config)
            
            # Start worker
            success = await worker.start()
            
            if success:
                self.workers[worker_id] = worker
                logger.info(f"Created worker {worker_id} of type {worker_type.value}")
                return worker_id
            else:
                logger.error(f"Failed to create worker {worker_id}")
                return ""
                
        except Exception as e:
            logger.error(f"Error creating worker: {e}")
            return ""
    
    async def stop_worker(self, worker_id: str, graceful: bool = True) -> bool:
        """Stop a specific worker"""
        try:
            worker = self.workers.get(worker_id)
            if not worker:
                logger.warning(f"Worker {worker_id} not found")
                return False
            
            success = await worker.stop(graceful)
            
            if success:
                del self.workers[worker_id]
                logger.info(f"Stopped worker {worker_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error stopping worker {worker_id}: {e}")
            return False
    
    async def restart_worker(self, worker_id: str) -> bool:
        """Restart a specific worker"""
        try:
            worker = self.workers.get(worker_id)
            if not worker:
                logger.warning(f"Worker {worker_id} not found")
                return False
            
            success = await worker.restart()
            
            if success:
                self.recovery_stats['auto_restarts'] += 1
                logger.info(f"Restarted worker {worker_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error restarting worker {worker_id}: {e}")
            return False
    
    async def stop_all_workers(self):
        """Stop all workers"""
        try:
            logger.info("Stopping all workers")
            
            # Get all worker IDs
            worker_ids = list(self.workers.keys())
            
            # Stop all workers concurrently
            tasks = [self.stop_worker(worker_id) for worker_id in worker_ids]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info("All workers stopped")
            
        except Exception as e:
            logger.error(f"Error stopping all workers: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Monitor all workers
                await self._monitor_all_workers()
                
                # Check for recovery actions
                await self._check_recovery_actions()
                
                # Update statistics
                await self._update_statistics()
                
                # Wait for next iteration
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)  # Brief delay before retry
    
    async def _recovery_loop(self):
        """Recovery loop for handling worker recovery"""
        while True:
            try:
                # Get next recovery action
                recovery_action = await self.recovery_queue.get()
                
                # Process recovery action
                await self._process_recovery_action(recovery_action)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in recovery loop: {e}")
                await asyncio.sleep(1)  # Brief delay before retry
    
    async def _monitor_all_workers(self):
        """Monitor all workers"""
        try:
            with self._lock:
                workers = list(self.workers.values())
            
            for worker in workers:
                try:
                    await self._monitor_worker(worker)
                except Exception as e:
                    logger.error(f"Error monitoring worker {worker.worker_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error monitoring all workers: {e}")
    
    async def _monitor_worker(self, worker: WorkerProcess):
        """Monitor a specific worker"""
        try:
            # Get worker metrics
            metrics = worker.get_metrics()
            
            # Check if recovery is needed
            if self._should_recover_worker(worker, metrics):
                await self._queue_recovery_action(worker, metrics)
                
        except Exception as e:
            logger.error(f"Error monitoring worker {worker.worker_id}: {e}")
    
    def _should_recover_worker(self, worker: WorkerProcess, metrics: WorkerMetrics) -> bool:
        """Check if worker needs recovery"""
        try:
            # Check if worker is failed
            if metrics.status == WorkerStatus.FAILED:
                return True
            
            # Check if worker is stalled
            if metrics.status == WorkerStatus.STALLED:
                return True
            
            # Check consecutive failures
            if metrics.consecutive_failures >= worker.config.max_consecutive_failures:
                return True
            
            # Check if recovery attempts exceeded
            if metrics.recovery_count >= worker.config.max_recovery_attempts:
                return False
            
            # Check health score
            if metrics.health_score < 0.3:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking recovery need for {worker.worker_id}: {e}")
            return False
    
    async def _queue_recovery_action(self, worker: WorkerProcess, metrics: WorkerMetrics):
        """Queue a recovery action"""
        try:
            recovery_action = {
                'worker_id': worker.worker_id,
                'worker_type': worker.worker_type,
                'action': 'restart',
                'reason': metrics.status.value,
                'metrics': metrics,
                'timestamp': datetime.utcnow()
            }
            
            await self.recovery_queue.put(recovery_action)
            
            logger.info(f"Queued recovery action for worker {worker.worker_id}")
            
        except Exception as e:
            logger.error(f"Error queuing recovery action: {e}")
    
    async def _process_recovery_action(self, recovery_action: Dict[str, Any]):
        """Process a recovery action"""
        try:
            worker_id = recovery_action['worker_id']
            action = recovery_action['action']
            
            logger.info(f"Processing recovery action: {action} for worker {worker_id}")
            
            if action == 'restart':
                success = await self.restart_worker(worker_id)
                
                if success:
                    self.recovery_stats['successful_recoveries'] += 1
                    logger.info(f"Successfully recovered worker {worker_id}")
                else:
                    self.recovery_stats['failed_recoveries'] += 1
                    logger.error(f"Failed to recover worker {worker_id}")
            
            self.recovery_stats['total_recoveries'] += 1
            
        except Exception as e:
            logger.error(f"Error processing recovery action: {e}")
    
    async def _check_recovery_actions(self):
        """Check for pending recovery actions"""
        try:
            # This would check for any additional recovery conditions
            # For now, we'll just log the current status
            total_workers = len(self.workers)
            healthy_workers = sum(1 for w in self.workers.values() if w.metrics.health_score > 0.7)
            
            logger.info(f"Worker status: {healthy_workers}/{total_workers} healthy")
            
        except Exception as e:
            logger.error(f"Error checking recovery actions: {e}")
    
    async def _update_statistics(self):
        """Update recovery statistics"""
        try:
            # Update worker counts
            total_workers = len(self.workers)
            healthy_workers = sum(1 for w in self.workers.values() if w.metrics.health_score > 0.7)
            failed_workers = sum(1 for w in self.workers.values() if w.metrics.status == WorkerStatus.FAILED)
            stalled_workers = sum(1 for w in self.workers.values() if w.metrics.status == WorkerStatus.STALLED)
            
            logger.info(f"Worker statistics: {healthy_workers} healthy, {failed_workers} failed, {stalled_workers} stalled out of {total_workers} total")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def get_worker_metrics(self, worker_id: str) -> Optional[WorkerMetrics]:
        """Get metrics for a specific worker"""
        try:
            worker = self.workers.get(worker_id)
            if worker:
                return worker.get_metrics()
            return None
        except Exception as e:
            logger.error(f"Error getting worker metrics: {e}")
            return None
    
    async def get_all_worker_metrics(self) -> Dict[str, WorkerMetrics]:
        """Get metrics for all workers"""
        try:
            return {
                worker_id: worker.get_metrics()
                for worker_id, worker in self.workers.items()
            }
        except Exception as e:
            logger.error(f"Error getting all worker metrics: {e}")
            return {}
    
    async def get_recovery_statistics(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        try:
            stats = self.recovery_stats.copy()
            
            # Add current worker counts
            total_workers = len(self.workers)
            healthy_workers = sum(1 for w in self.workers.values() if w.metrics.health_score > 0.7)
            
            stats.update({
                'total_workers': total_workers,
                'healthy_workers': healthy_workers,
                'health_percentage': (healthy_workers / total_workers * 100) if total_workers > 0 else 0
            })
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting recovery statistics: {e}")
            return {}
    
    async def add_task_to_worker(self, worker_type: WorkerType, task: Dict[str, Any]) -> bool:
        """Add a task to a worker of specific type"""
        try:
            # Find available worker of the specified type
            available_workers = [
                worker for worker in self.workers.values()
                if worker.worker_type == worker_type and worker.status == WorkerStatus.RUNNING
            ]
            
            if not available_workers:
                logger.warning(f"No available workers of type {worker_type.value}")
                return False
            
            # Select worker with lowest load
            best_worker = min(available_workers, key=lambda w: w.metrics.tasks_processed)
            
            # Add task to worker
            await best_worker.add_task(task)
            
            logger.debug(f"Added task to worker {best_worker.worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding task to worker: {e}")
            return False


# Global worker recovery system instance
worker_recovery_system = WorkerRecoverySystem()


async def get_worker_status(worker_id: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific worker"""
    try:
        metrics = await worker_recovery_system.get_worker_metrics(worker_id)
        if metrics:
            return {
                'worker_id': metrics.worker_id,
                'worker_type': metrics.worker_type.value,
                'status': metrics.status.value,
                'health_score': metrics.health_score,
                'cpu_usage': metrics.cpu_usage,
                'memory_usage': metrics.memory_usage,
                'tasks_processed': metrics.tasks_processed,
                'tasks_failed': metrics.tasks_failed,
                'recovery_count': metrics.recovery_count
            }
        return None
    except Exception as e:
        logger.error(f"Error getting worker status: {e}")
        return None


async def get_all_worker_status() -> Dict[str, Any]:
    """Get status of all workers"""
    try:
        metrics = await worker_recovery_system.get_all_worker_metrics()
        return {
            worker_id: {
                'worker_id': metrics.worker_id,
                'worker_type': metrics.worker_type.value,
                'status': metrics.status.value,
                'health_score': metrics.health_score,
                'cpu_usage': metrics.cpu_usage,
                'memory_usage': metrics.memory_usage,
                'tasks_processed': metrics.tasks_processed,
                'tasks_failed': metrics.tasks_failed,
                'recovery_count': metrics.recovery_count
            }
            for worker_id, metrics in metrics.items()
        }
    except Exception as e:
        logger.error(f"Error getting all worker status: {e}")
        return {}


async def create_worker(worker_type: str, worker_id: Optional[str] = None) -> str:
    """Create a new worker"""
    try:
        # Convert string to enum
        worker_type_enum = WorkerType(worker_type)
        
        # Create worker
        worker_id_result = await worker_recovery_system.create_worker(worker_type_enum, worker_id)
        
        if worker_id_result:
            return f"Worker {worker_id_result} created successfully"
        else:
            return "Failed to create worker"
            
    except Exception as e:
        logger.error(f"Error creating worker: {e}")
        return f"Error creating worker: {e}"


async def restart_worker(worker_id: str) -> str:
    """Restart a specific worker"""
    try:
        success = await worker_recovery_system.restart_worker(worker_id)
        
        if success:
            return f"Worker {worker_id} restarted successfully"
        else:
            return f"Failed to restart worker {worker_id}"
            
    except Exception as e:
        logger.error(f"Error restarting worker: {e}")
        return f"Error restarting worker: {e}"


async def get_recovery_statistics() -> Dict[str, Any]:
    """Get recovery statistics"""
    try:
        return await worker_recovery_system.get_recovery_statistics()
    except Exception as e:
        logger.error(f"Error getting recovery statistics: {e}")
        return {'error': str(e)}


# Initialize worker recovery system
async def initialize_worker_recovery():
    """Initialize worker recovery system"""
    try:
        await worker_recovery_system.start()
        logger.info("Worker recovery system initialized")
        return "Worker recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing worker recovery system: {e}")
        return f"Error initializing worker recovery system: {e}"


# Cleanup function
async def cleanup_worker_recovery():
    """Cleanup worker recovery system"""
    try:
        await worker_recovery_system.stop()
        logger.info("Worker recovery system cleaned up")
        return "Worker recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up worker recovery system: {e}")
        return f"Error cleaning up worker recovery system: {e}"
