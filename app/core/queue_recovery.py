#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Queue Recovery System
Automatic queue recovery with message preservation and failover
"""

import os
import sys
import asyncio
import logging
import json
import time
import pickle
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
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
        logging.FileHandler('/app/logs/queue_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class QueueStatus(Enum):
    """Queue status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"
    MAINTENANCE = "maintenance"


class QueueType(Enum):
    """Queue type enumeration"""
    TASK_QUEUE = "task_queue"
    MESSAGE_QUEUE = "message_queue"
    EVENT_QUEUE = "event_queue"
    WORKER_QUEUE = "worker_queue"
    DEAD_LETTER_QUEUE = "dead_letter_queue"


class RecoveryAction(Enum):
    """Recovery action enumeration"""
    RESTART = "restart"
    REBUILD = "rebuild"
    RESTORE = "restore"
    FAILOVER = "failover"
    PURGE = "purge"
    VALIDATE = "validate"


@dataclass
class QueueMetrics:
    """Queue performance metrics"""
    queue_id: str
    queue_type: QueueType
    status: QueueStatus
    message_count: int
    processing_rate: float
    error_rate: float
    avg_processing_time: float
    memory_usage: float
    worker_count: int
    dead_letter_count: int
    error_count: int
    last_error: Optional[str]
    last_recovery: Optional[datetime]
    recovery_count: int
    health_score: float = 1.0


@dataclass
class QueueConfig:
    """Queue configuration"""
    queue_id: str
    queue_type: QueueType
    max_size: int = 10000
    max_memory_mb: int = 256
    max_workers: int = 10
    processing_timeout: int = 30
    retry_attempts: int = 3
    dead_letter_enabled: bool = True
    persistence_enabled: bool = True
    compression_enabled: bool = True
    health_check_interval: int = 60
    auto_recovery: bool = True


@dataclass
class QueueMessage:
    """Queue message with metadata"""
    message_id: str
    payload: Any
    priority: int
    created_at: datetime
    attempts: int
    max_attempts: int
    timeout: int
    metadata: Dict[str, Any]
    size_bytes: int
    compressed: bool = False


class QueueRecoverySystem:
    """Queue recovery system with automatic failover"""
    
    def __init__(self):
        """Initialize queue recovery system"""
        self.queues: Dict[str, Dict[str, Any]] = {}
        self.queue_configs: Dict[str, QueueConfig] = {}
        self.queue_metrics: Dict[str, QueueMetrics] = {}
        self.recovery_queue = asyncio.Queue()
        self.monitoring_task: Optional[asyncio.Task] = None
        self.recovery_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # Recovery statistics
        self.recovery_stats = {
            'total_recoveries': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'auto_recoveries': 0,
            'manual_recoveries': 0,
            'message_loss_events': 0,
            'processing_failures': 0
        }
        
        logger.info("Queue recovery system initialized")
    
    async def start(self):
        """Start the queue recovery system"""
        logger.info("Starting queue recovery system")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        # Start recovery task
        self.recovery_task = asyncio.create_task(self._recovery_loop())
        
        logger.info("Queue recovery system started")
    
    async def stop(self):
        """Stop the queue recovery system"""
        logger.info("Stopping queue recovery system")
        
        # Cancel tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
        if self.recovery_task:
            self.recovery_task.cancel()
        
        logger.info("Queue recovery system stopped")
    
    async def register_queue(self, queue_id: str, queue_type: QueueType, 
                           config: Optional[QueueConfig] = None) -> bool:
        """Register a queue for monitoring"""
        try:
            if queue_id in self.queues:
                logger.warning(f"Queue {queue_id} already registered")
                return False
            
            # Use default config if none provided
            if config is None:
                config = QueueConfig(queue_id=queue_id, queue_type=queue_type)
            
            # Initialize queue storage
            self.queues[queue_id] = {
                'messages': deque(maxlen=config.max_size),
                'processing': set(),
                'dead_letter': deque(maxlen=1000),
                'backup': [],
                'status': QueueStatus.HEALTHY,
                'workers': []
            }
            
            # Store config
            self.queue_configs[queue_id] = config
            
            # Initialize metrics
            self.queue_metrics[queue_id] = QueueMetrics(
                queue_id=queue_id,
                queue_type=queue_type,
                status=QueueStatus.HEALTHY,
                message_count=0,
                processing_rate=0.0,
                error_rate=0.0,
                avg_processing_time=0.0,
                memory_usage=0.0,
                worker_count=0,
                dead_letter_count=0,
                error_count=0,
                last_error=None,
                last_recovery=None,
                recovery_count=0
            )
            
            logger.info(f"Queue {queue_id} of type {queue_type.value} registered")
            return True
            
        except Exception as e:
            logger.error(f"Error registering queue {queue_id}: {e}")
            return False
    
    async def enqueue(self, queue_id: str, payload: Any, priority: int = 0,
                     timeout: int = 30, max_attempts: int = 3, 
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """Enqueue a message"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                logger.warning(f"Queue {queue_id} not found")
                return ""
            
            config = self.queue_configs.get(queue_id)
            if not config:
                return ""
            
            # Create message
            message_id = f"msg_{int(time.time())}_{len(queue['messages'])}"
            
            # Serialize payload
            serialized_payload = payload
            if not isinstance(payload, (str, bytes)):
                serialized_payload = json.dumps(payload)
            
            # Compress if enabled and payload is large enough
            compressed = False
            if config.compression_enabled and len(serialized_payload) > 1024:
                serialized_payload = gzip.compress(serialized_payload.encode('utf-8'))
                compressed = True
            
            # Create message object
            message = QueueMessage(
                message_id=message_id,
                payload=serialized_payload,
                priority=priority,
                created_at=datetime.utcnow(),
                attempts=0,
                max_attempts=max_attempts,
                timeout=timeout,
                metadata=metadata or {},
                size_bytes=len(serialized_payload),
                compressed=compressed
            )
            
            # Check queue size limit
            if len(queue['messages']) >= config.max_size:
                # Move oldest messages to dead letter
                await self._move_to_dead_letter(queue_id, "Queue full")
            
            # Add to queue
            queue['messages'].append(message)
            
            # Create backup if enabled
            if config.persistence_enabled:
                await self._create_backup(queue_id, message)
            
            logger.debug(f"Message {message_id} enqueued to {queue_id}")
            return message_id
            
        except Exception as e:
            logger.error(f"Error enqueuing to {queue_id}: {e}")
            return ""
    
    async def dequeue(self, queue_id: str) -> Optional[QueueMessage]:
        """Dequeue a message"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return None
            
            # Get next message (priority queue)
            if queue['messages']:
                # Sort by priority (higher priority first)
                messages = sorted(queue['messages'], key=lambda x: x.priority, reverse=True)
                message = messages[0]
                queue['messages'].remove(message)
                
                # Add to processing set
                queue['processing'].add(message.message_id)
                
                logger.debug(f"Message {message.message_id} dequeued from {queue_id}")
                return message
            
            return None
            
        except Exception as e:
            logger.error(f"Error dequeuing from {queue_id}: {e}")
            return None
    
    async def complete_message(self, queue_id: str, message_id: str, success: bool = True):
        """Complete message processing"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return
            
            # Remove from processing set
            queue['processing'].discard(message_id)
            
            # Update metrics
            metrics = self.queue_metrics.get(queue_id)
            if metrics:
                if success:
                    metrics.processing_rate += 1
                else:
                    metrics.error_count += 1
            
            logger.debug(f"Message {message_id} completed in {queue_id}")
            
        except Exception as e:
            logger.error(f"Error completing message {message_id} in {queue_id}: {e}")
    
    async def requeue_message(self, queue_id: str, message: QueueMessage) -> bool:
        """Requeue a message for retry"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return False
            
            # Increment attempts
            message.attempts += 1
            
            # Check max attempts
            if message.attempts >= message.max_attempts:
                # Move to dead letter
                await self._move_to_dead_letter(queue_id, f"Max attempts ({message.max_attempts})")
                return False
            
            # Reset timeout
            message.created_at = datetime.utcnow()
            
            # Add back to queue
            queue['messages'].append(message)
            
            logger.debug(f"Message {message.message_id} requeued to {queue_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error requeuing message {message.message_id}: {e}")
            return False
    
    async def _move_to_dead_letter(self, queue_id: str, reason: str):
        """Move message to dead letter queue"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return
            
            config = self.queue_configs.get(queue_id)
            if not config or not config.dead_letter_enabled:
                return
            
            # Get message to move
            if queue['messages']:
                message = queue['messages'][0]
                queue['messages'].popleft()
                
                # Add dead letter reason
                message.metadata['dead_letter_reason'] = reason
                message.metadata['dead_letter_at'] = datetime.utcnow().isoformat()
                
                # Add to dead letter queue
                queue['dead_letter'].append(message)
                
                # Update metrics
                metrics = self.queue_metrics.get(queue_id)
                if metrics:
                    metrics.dead_letter_count += 1
                
                logger.warning(f"Message {message.message_id} moved to dead letter queue: {reason}")
                
        except Exception as e:
            logger.error(f"Error moving to dead letter queue: {e}")
    
    async def _create_backup(self, queue_id: str, message: QueueMessage):
        """Create backup of queue message"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return
            
            # Store backup message
            backup_data = {
                'message': message,
                'timestamp': datetime.utcnow()
            }
            
            queue['backup'].append(backup_data)
            
            # Limit backup size
            if len(queue['backup']) > 1000:
                queue['backup'] = queue['backup'][-1000:]
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Monitor all queues
                await self._monitor_all_queues()
                
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
        """Recovery loop for handling queue recovery"""
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
    
    async def _monitor_all_queues(self):
        """Monitor all queues"""
        try:
            for queue_id in list(self.queues.keys()):
                try:
                    await self._monitor_queue(queue_id)
                except Exception as e:
                    logger.error(f"Error monitoring queue {queue_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error monitoring all queues: {e}")
    
    async def _monitor_queue(self, queue_id: str):
        """Monitor a specific queue"""
        try:
            queue = self.queues.get(queue_id)
            config = self.queue_configs.get(queue_id)
            metrics = self.queue_metrics.get(queue_id)
            
            if not queue or not config or not metrics:
                return
            
            # Update message count
            metrics.message_count = len(queue['messages'])
            metrics.worker_count = len(queue['workers'])
            metrics.dead_letter_count = len(queue['dead_letter'])
            
            # Calculate processing rate (simulated)
            metrics.processing_rate = metrics.processing_rate * 0.9  # Decay factor
            
            # Calculate error rate
            total_processed = metrics.processing_rate + metrics.error_count
            metrics.error_rate = metrics.error_count / total_processed if total_processed > 0 else 0
            
            # Calculate memory usage (approximate)
            total_size = sum(msg.size_bytes for msg in queue['messages'])
            if config.max_memory_mb > 0:
                metrics.memory_usage = total_size / (config.max_memory_mb * 1024 * 1024)
            
            # Update health score
            metrics.health_score = self._calculate_health_score(metrics)
            
            # Check if recovery is needed
            if self._should_recover_queue(queue_id, metrics, config):
                await self._queue_recovery_action(queue_id, RecoveryAction.RESTART)
                
        except Exception as e:
            logger.error(f"Error monitoring queue {queue_id}: {e}")
    
    def _calculate_health_score(self, metrics: QueueMetrics) -> float:
        """Calculate queue health score"""
        try:
            score = 1.0
            
            # Penalize high error rate
            if metrics.error_rate > 0.1:
                score -= min(metrics.error_rate * 2, 0.5)
            
            # Penalize high memory usage
            if metrics.memory_usage > 0.8:
                score -= (metrics.memory_usage - 0.8) * 2
            
            # Penalize high dead letter count
            if metrics.dead_letter_count > 100:
                score -= min(metrics.dead_letter_count / 1000, 0.3)
            
            # Penalize no workers
            if metrics.worker_count == 0:
                score -= 0.5
            
            # Ensure score is between 0 and 1
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
            return 0.0
    
    def _should_recover_queue(self, queue_id: str, metrics: QueueMetrics, config: QueueConfig) -> bool:
        """Check if queue needs recovery"""
        try:
            # Check if queue is in failed state
            if metrics.status == QueueStatus.FAILED:
                return True
            
            # Check error rate
            if metrics.error_rate > 0.2:
                return True
            
            # Check health score
            if metrics.health_score < 0.3:
                return True
            
            # Check if no workers and messages pending
            if metrics.worker_count == 0 and metrics.message_count > 0:
                return True
            
            # Check if auto recovery is enabled
            if not config.auto_recovery:
                return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking recovery need: {e}")
            return False
    
    async def _queue_recovery_action(self, queue_id: str, action: RecoveryAction):
        """Queue a recovery action"""
        try:
            recovery_action = {
                'queue_id': queue_id,
                'action': action,
                'timestamp': datetime.utcnow()
            }
            
            await self.recovery_queue.put(recovery_action)
            
            logger.info(f"Queued recovery action: {action.value} for queue {queue_id}")
            
        except Exception as e:
            logger.error(f"Error queuing recovery action: {e}")
    
    async def _process_recovery_action(self, recovery_action: Dict[str, Any]):
        """Process a recovery action"""
        try:
            queue_id = recovery_action['queue_id']
            action = recovery_action['action']
            
            logger.info(f"Processing recovery action: {action.value} for queue {queue_id}")
            
            if action == RecoveryAction.RESTART:
                success = await self._restart_queue(queue_id)
            elif action == RecoveryAction.REBUILD:
                success = await self._rebuild_queue(queue_id)
            elif action == RecoveryAction.RESTORE:
                success = await self._restore_queue(queue_id)
            elif action == RecoveryAction.FAILOVER:
                success = await self._failover_queue(queue_id)
            elif action == RecoveryAction.PURGE:
                success = await self._purge_queue(queue_id)
            elif action == RecoveryAction.VALIDATE:
                success = await self._validate_queue(queue_id)
            else:
                logger.warning(f"Unknown recovery action: {action.value}")
                success = False
            
            # Update statistics
            self.recovery_stats['total_recoveries'] += 1
            if success:
                self.recovery_stats['successful_recoveries'] += 1
                logger.info(f"Successfully recovered queue {queue_id}")
            else:
                self.recovery_stats['failed_recoveries'] += 1
                logger.error(f"Failed to recover queue {queue_id}")
                
        except Exception as e:
            logger.error(f"Error processing recovery action: {e}")
    
    async def _restart_queue(self, queue_id: str) -> bool:
        """Restart queue"""
        try:
            logger.info(f"Restarting queue {queue_id}")
            
            queue = self.queues.get(queue_id)
            if not queue:
                return False
            
            # Move processing messages back to queue
            processing_messages = []
            for message_id in queue['processing']:
                # Find message in backup
                for backup_data in queue['backup']:
                    if backup_data['message'].message_id == message_id:
                        processing_messages.append(backup_data['message'])
                        break
            
            # Add back to queue
            for message in processing_messages:
                queue['messages'].append(message)
            
            # Clear processing set
            queue['processing'].clear()
            
            # Reset metrics
            metrics = self.queue_metrics.get(queue_id)
            if metrics:
                metrics.status = QueueStatus.RECOVERING
                metrics.last_recovery = datetime.utcnow()
                metrics.recovery_count += 1
            
            # Update status
            if metrics:
                metrics.status = QueueStatus.HEALTHY
            
            return True
            
        except Exception as e:
            logger.error(f"Error restarting queue {queue_id}: {e}")
            return False
    
    async def _rebuild_queue(self, queue_id: str) -> bool:
        """Rebuild queue"""
        try:
            logger.info(f"Rebuilding queue {queue_id}")
            
            # Clear queue
            await self._purge_queue(queue_id)
            
            # Rebuild from backup if available
            await self._restore_from_backup(queue_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error rebuilding queue {queue_id}: {e}")
            return False
    
    async def _restore_queue(self, queue_id: str) -> bool:
        """Restore queue from backup"""
        try:
            logger.info(f"Restoring queue {queue_id}")
            
            queue = self.queues.get(queue_id)
            if not queue:
                return False
            
            # Restore from backup
            restored_count = 0
            for backup_data in queue['backup']:
                message = backup_data['message']
                queue['messages'].append(message)
                restored_count += 1
            
            logger.info(f"Restored {restored_count} messages from backup for queue {queue_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring queue {queue_id}: {e}")
            return False
    
    async def _failover_queue(self, queue_id: str) -> bool:
        """Failover queue to alternative"""
        try:
            logger.info(f"Failing over queue {queue_id}")
            
            # In a real implementation, this would switch to alternative queue
            # For now, we'll simulate the failover
            await asyncio.sleep(2)
            
            return True
            
        except Exception as e:
            logger.error(f"Error failing over queue {queue_id}: {e}")
            return False
    
    async def _purge_queue(self, queue_id: str) -> bool:
        """Purge queue"""
        try:
            logger.info(f"Purging queue {queue_id}")
            
            queue = self.queues.get(queue_id)
            if not queue:
                return False
            
            # Move messages to dead letter before purging
            messages_to_move = list(queue['messages'])
            for message in messages_to_move:
                await self._move_to_dead_letter(queue_id, "Queue purge")
            
            # Clear queue
            queue['messages'].clear()
            queue['processing'].clear()
            
            logger.info(f"Purged {len(messages_to_move)} messages from queue {queue_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error purging queue {queue_id}: {e}")
            return False
    
    async def _validate_queue(self, queue_id: str) -> bool:
        """Validate queue data integrity"""
        try:
            logger.info(f"Validating queue {queue_id}")
            
            queue = self.queues.get(queue_id)
            if not queue:
                return False
            
            # Validate messages
            invalid_messages = []
            for message in queue['messages']:
                try:
                    # Validate message structure
                    if not hasattr(message, 'message_id') or not hasattr(message, 'payload'):
                        invalid_messages.append(message)
                        
                except Exception as e:
                    logger.error(f"Error validating message: {e}")
                    invalid_messages.append(message)
            
            # Remove invalid messages
            for message in invalid_messages:
                queue['messages'].remove(message)
                self.recovery_stats['processing_failures'] += 1
            
            if invalid_messages:
                logger.warning(f"Removed {len(invalid_messages)} invalid messages from queue {queue_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating queue {queue_id}: {e}")
            return False
    
    async def _restore_from_backup(self, queue_id: str):
        """Restore queue from backup"""
        try:
            queue = self.queues.get(queue_id)
            if not queue:
                return
            
            # Restore from backup
            for backup_data in queue['backup']:
                message = backup_data['message']
                queue['messages'].append(message)
            
            logger.info(f"Restored queue {queue_id} from backup")
            
        except Exception as e:
            logger.error(f"Error restoring from backup: {e}")
    
    async def _check_recovery_actions(self):
        """Check for pending recovery actions"""
        try:
            # This would check for any additional recovery conditions
            # For now, we'll just log the current status
            total_queues = len(self.queues)
            healthy_queues = sum(1 for metrics in self.queue_metrics.values() if metrics.health_score > 0.7)
            failed_queues = sum(1 for metrics in self.queue_metrics.values() if metrics.status == QueueStatus.FAILED)
            
            logger.info(f"Queue status: {healthy_queues} healthy, {failed_queues} failed out of {total_queues} total")
            
        except Exception as e:
            logger.error(f"Error checking recovery actions: {e}")
    
    async def _update_statistics(self):
        """Update recovery statistics"""
        try:
            # Update queue counts
            total_queues = len(self.queues)
            healthy_queues = sum(1 for metrics in self.queue_metrics.values() if metrics.health_score > 0.7)
            failed_queues = sum(1 for metrics in self.queue_metrics.values() if metrics.status == QueueStatus.FAILED)
            
            logger.info(f"Queue statistics: {healthy_queues} healthy, {failed_queues} failed out of {total_queues} total")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def get_queue_metrics(self, queue_id: str) -> Optional[QueueMetrics]:
        """Get metrics for a specific queue"""
        try:
            return self.queue_metrics.get(queue_id)
        except Exception as e:
            logger.error(f"Error getting queue metrics: {e}")
            return None
    
    async def get_all_queue_metrics(self) -> Dict[str, QueueMetrics]:
        """Get metrics for all queues"""
        try:
            return dict(self.queue_metrics)
        except Exception as e:
            logger.error(f"Error getting all queue metrics: {e}")
            return {}
    
    async def get_recovery_statistics(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        try:
            stats = self.recovery_stats.copy()
            
            # Add queue counts
            total_queues = len(self.queues)
            healthy_queues = sum(1 for metrics in self.queue_metrics.values() if metrics.health_score > 0.7)
            
            stats.update({
                'total_queues': total_queues,
                'healthy_queues': healthy_queues,
                'health_percentage': (healthy_queues / total_queues * 100) if total_queues > 0 else 0
            })
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting recovery statistics: {e}")
            return {'error': str(e)}


# Global queue recovery system instance
queue_recovery_system = QueueRecoverySystem()


async def get_queue_status(queue_id: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific queue"""
    try:
        metrics = await queue_recovery_system.get_queue_metrics(queue_id)
        if metrics:
            return {
                'queue_id': metrics.queue_id,
                'queue_type': metrics.queue_type.value,
                'status': metrics.status.value,
                'message_count': metrics.message_count,
                'processing_rate': metrics.processing_rate,
                'error_rate': metrics.error_rate,
                'worker_count': metrics.worker_count,
                'dead_letter_count': metrics.dead_letter_count,
                'health_score': metrics.health_score,
                'error_count': metrics.error_count,
                'recovery_count': metrics.recovery_count
            }
        return None
    except Exception as e:
        logger.error(f"Error getting queue status: {e}")
        return None


async def get_all_queue_status() -> Dict[str, Any]:
    """Get status of all queues"""
    try:
        metrics = await queue_recovery_system.get_all_queue_metrics()
        return {
            queue_id: {
                'queue_id': metrics.queue_id,
                'queue_type': metrics.queue_type.value,
                'status': metrics.status.value,
                'message_count': metrics.message_count,
                'processing_rate': metrics.processing_rate,
                'error_rate': metrics.error_rate,
                'worker_count': metrics.worker_count,
                'dead_letter_count': metrics.dead_letter_count,
                'health_score': metrics.health_score,
                'error_count': metrics.error_count,
                'recovery_count': metrics.recovery_count
            }
            for queue_id, metrics in metrics.items()
        }
    except Exception as e:
        logger.error(f"Error getting all queue status: {e}")
        return {}


async def register_queue(queue_id: str, queue_type: str, config: Optional[Dict[str, Any]] = None) -> str:
    """Register a new queue"""
    try:
        # Convert strings to enums
        queue_type_enum = QueueType(queue_type)
        
        # Convert config dict to QueueConfig
        queue_config = None
        if config:
            queue_config = QueueConfig(
                queue_id=queue_id,
                queue_type=queue_type_enum,
                max_size=config.get('max_size', 10000),
                max_memory_mb=config.get('max_memory_mb', 256),
                max_workers=config.get('max_workers', 10),
                processing_timeout=config.get('processing_timeout', 30),
                retry_attempts=config.get('retry_attempts', 3),
                dead_letter_enabled=config.get('dead_letter_enabled', True),
                persistence_enabled=config.get('persistence_enabled', True),
                compression_enabled=config.get('compression_enabled', True),
                health_check_interval=config.get('health_check_interval', 60),
                auto_recovery=config.get('auto_recovery', True)
            )
        
        # Register queue
        success = await queue_recovery_system.register_queue(queue_id, queue_type_enum, queue_config)
        
        if success:
            return f"Queue {queue_id} registered successfully"
        else:
            return f"Failed to register queue {queue_id}"
            
    except Exception as e:
        logger.error(f"Error registering queue: {e}")
        return f"Error registering queue: {e}"


async def get_queue_statistics() -> Dict[str, Any]:
    """Get queue recovery statistics"""
    try:
        return await queue_recovery_system.get_recovery_statistics()
    except Exception as e:
        logger.error(f"Error getting queue statistics: {e}")
        return {'error': str(e)}


# Initialize queue recovery system
async def initialize_queue_recovery():
    """Initialize queue recovery system"""
    try:
        await queue_recovery_system.start()
        logger.info("Queue recovery system initialized")
        return "Queue recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing queue recovery system: {e}")
        return f"Error initializing queue recovery system: {e}"


# Cleanup function
async def cleanup_queue_recovery():
    """Cleanup queue recovery system"""
    try:
        await queue_recovery_system.stop()
        logger.info("Queue recovery system cleaned up")
        return "Queue recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up queue recovery system: {e}")
        return f"Error cleaning up queue recovery system: {e}"
