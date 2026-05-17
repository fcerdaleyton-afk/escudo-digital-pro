#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Cache Recovery System
Automatic cache recovery with data validation and failover
"""

import os
import sys
import asyncio
import logging
import json
import time
import hashlib
import pickle
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
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
        logging.FileHandler('/app/logs/cache_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CacheStatus(Enum):
    """Cache status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"
    MAINTENANCE = "maintenance"


class CacheType(Enum):
    """Cache type enumeration"""
    MEMORY = "memory"
    REDIS = "redis"
    FILE = "file"
    DISTRIBUTED = "distributed"


class RecoveryAction(Enum):
    """Recovery action enumeration"""
    RESTART = "restart"
    REBUILD = "rebuild"
    RESTORE = "restore"
    FAILOVER = "failover"
    CLEAR = "clear"
    VALIDATE = "validate"


@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    cache_id: str
    cache_type: CacheType
    status: CacheStatus
    hit_rate: float
    miss_rate: float
    eviction_rate: float
    memory_usage: float
    key_count: int
    size_bytes: int
    avg_get_time: float
    avg_set_time: float
    error_count: int
    last_error: Optional[str]
    last_recovery: Optional[datetime]
    recovery_count: int
    health_score: float = 1.0


@dataclass
class CacheConfig:
    """Cache configuration"""
    cache_id: str
    cache_type: CacheType
    max_memory_mb: int = 512
    max_keys: int = 100000
    ttl_seconds: int = 3600
    cleanup_interval: int = 300
    health_check_interval: int = 60
    max_error_rate: float = 0.05
    max_memory_usage: float = 0.8
    auto_recovery: bool = True
    backup_enabled: bool = True
    validation_enabled: bool = True
    compression_enabled: bool = True


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    ttl: Optional[int]
    created_at: datetime
    accessed_at: datetime
    access_count: int
    size_bytes: int
    checksum: str
    compressed: bool = False


class CacheRecoverySystem:
    """Cache recovery system with automatic failover"""
    
    def __init__(self):
        """Initialize cache recovery system"""
        self.caches: Dict[str, Dict[str, Any]] = {}
        self.cache_configs: Dict[str, CacheConfig] = {}
        self.cache_metrics: Dict[str, CacheMetrics] = {}
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
            'data_loss_events': 0,
            'validation_failures': 0
        }
        
        logger.info("Cache recovery system initialized")
    
    async def start(self):
        """Start the cache recovery system"""
        logger.info("Starting cache recovery system")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        # Start recovery task
        self.recovery_task = asyncio.create_task(self._recovery_loop())
        
        logger.info("Cache recovery system started")
    
    async def stop(self):
        """Stop the cache recovery system"""
        logger.info("Stopping cache recovery system")
        
        # Cancel tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
        if self.recovery_task:
            self.recovery_task.cancel()
        
        logger.info("Cache recovery system stopped")
    
    async def register_cache(self, cache_id: str, cache_type: CacheType, 
                           config: Optional[CacheConfig] = None) -> bool:
        """Register a cache for monitoring"""
        try:
            if cache_id in self.caches:
                logger.warning(f"Cache {cache_id} already registered")
                return False
            
            # Use default config if none provided
            if config is None:
                config = CacheConfig(cache_id=cache_id, cache_type=cache_type)
            
            # Initialize cache storage
            self.caches[cache_id] = {
                'data': {},
                'metadata': {},
                'backup': {},
                'status': CacheStatus.HEALTHY
            }
            
            # Store config
            self.cache_configs[cache_id] = config
            
            # Initialize metrics
            self.cache_metrics[cache_id] = CacheMetrics(
                cache_id=cache_id,
                cache_type=cache_type,
                status=CacheStatus.HEALTHY,
                hit_rate=0.0,
                miss_rate=0.0,
                eviction_rate=0.0,
                memory_usage=0.0,
                key_count=0,
                size_bytes=0,
                avg_get_time=0.0,
                avg_set_time=0.0,
                error_count=0,
                last_error=None,
                last_recovery=None,
                recovery_count=0
            )
            
            logger.info(f"Cache {cache_id} of type {cache_type.value} registered")
            return True
            
        except Exception as e:
            logger.error(f"Error registering cache {cache_id}: {e}")
            return False
    
    async def get(self, cache_id: str, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                logger.warning(f"Cache {cache_id} not found")
                return None
            
            start_time = time.time()
            
            # Check if key exists
            entry = cache['data'].get(key)
            if not entry:
                self._update_miss_metrics(cache_id)
                return None
            
            # Check TTL
            if entry.ttl and (datetime.utcnow() - entry.created_at).total_seconds() > entry.ttl:
                del cache['data'][key]
                self._update_miss_metrics(cache_id)
                return None
            
            # Update access metrics
            entry.accessed_at = datetime.utcnow()
            entry.access_count += 1
            
            # Decompress if needed
            value = entry.value
            if entry.compressed:
                value = gzip.decompress(value).decode('utf-8')
                if value.startswith('{') or value.startswith('['):
                    value = json.loads(value)
            
            # Update hit metrics
            self._update_hit_metrics(cache_id, time.time() - start_time)
            
            return value
            
        except Exception as e:
            logger.error(f"Error getting from cache {cache_id}: {e}")
            self._update_error_metrics(cache_id, str(e))
            return None
    
    async def set(self, cache_id: str, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                logger.warning(f"Cache {cache_id} not found")
                return False
            
            config = self.cache_configs.get(cache_id)
            if not config:
                return False
            
            start_time = time.time()
            
            # Serialize value
            serialized_value = value
            if not isinstance(value, (str, bytes)):
                serialized_value = json.dumps(value)
            
            # Compress if enabled and value is large enough
            compressed = False
            if config.compression_enabled and len(serialized_value) > 1024:
                serialized_value = gzip.compress(serialized_value.encode('utf-8'))
                compressed = True
            
            # Calculate checksum
            checksum = hashlib.md5(str(serialized_value).encode('utf-8')).hexdigest()
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=serialized_value,
                ttl=ttl or config.ttl_seconds,
                created_at=datetime.utcnow(),
                accessed_at=datetime.utcnow(),
                access_count=0,
                size_bytes=len(serialized_value),
                checksum=checksum,
                compressed=compressed
            )
            
            # Check memory limits
            if self._should_evict(cache_id, entry.size_bytes):
                await self._evict_lru(cache_id)
            
            # Store entry
            cache['data'][key] = entry
            
            # Create backup if enabled
            if config.backup_enabled:
                await self._create_backup(cache_id, key, entry)
            
            # Update metrics
            self._update_set_metrics(cache_id, time.time() - start_time)
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting in cache {cache_id}: {e}")
            self._update_error_metrics(cache_id, str(e))
            return False
    
    async def delete(self, cache_id: str, key: str) -> bool:
        """Delete key from cache"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return False
            
            if key in cache['data']:
                del cache['data'][key]
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting from cache {cache_id}: {e}")
            return False
    
    async def clear(self, cache_id: str) -> bool:
        """Clear all data from cache"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return False
            
            # Create backup before clearing
            if self.cache_configs[cache_id].backup_enabled:
                await self._create_full_backup(cache_id)
            
            # Clear cache
            cache['data'].clear()
            
            logger.info(f"Cache {cache_id} cleared")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing cache {cache_id}: {e}")
            return False
    
    def _should_evict(self, cache_id: str, entry_size: int) -> bool:
        """Check if eviction is needed"""
        try:
            config = self.cache_configs.get(cache_id)
            if not config:
                return False
            
            cache = self.caches.get(cache_id)
            if not cache:
                return False
            
            # Check key count limit
            if len(cache['data']) >= config.max_keys:
                return True
            
            # Check memory limit (approximate)
            total_size = sum(entry.size_bytes for entry in cache['data'].values())
            if total_size + entry_size > config.max_memory_mb * 1024 * 1024:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking eviction need: {e}")
            return False
    
    async def _evict_lru(self, cache_id: str):
        """Evict least recently used entries"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return
            
            # Sort by last access time
            entries = sorted(cache['data'].values(), key=lambda x: x.accessed_at)
            
            # Evict 10% of entries
            evict_count = max(1, len(entries) // 10)
            
            for i in range(evict_count):
                key = entries[i].key
                del cache['data'][key]
            
            logger.info(f"Evicted {evict_count} entries from cache {cache_id}")
            
        except Exception as e:
            logger.error(f"Error evicting from cache {cache_id}: {e}")
    
    async def _create_backup(self, cache_id: str, key: str, entry: CacheEntry):
        """Create backup of cache entry"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return
            
            # Store backup entry
            cache['backup'][key] = {
                'entry': entry,
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Error creating backup for {cache_id}:{key}: {e}")
    
    async def _create_full_backup(self, cache_id: str):
        """Create full backup of cache"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return
            
            # Create full backup
            cache['backup'] = {
                'full_backup': {
                    'data': dict(cache['data']),
                    'timestamp': datetime.utcnow()
                }
            }
            
            logger.info(f"Created full backup for cache {cache_id}")
            
        except Exception as e:
            logger.error(f"Error creating full backup for {cache_id}: {e}")
    
    def _update_hit_metrics(self, cache_id: str, get_time: float):
        """Update hit metrics"""
        try:
            metrics = self.cache_metrics.get(cache_id)
            if not metrics:
                return
            
            # Update hit rate
            total_requests = metrics.hit_count + metrics.miss_count + 1
            metrics.hit_count = getattr(metrics, 'hit_count', 0) + 1
            metrics.hit_rate = metrics.hit_count / total_requests if total_requests > 0 else 0
            metrics.miss_rate = metrics.miss_count / total_requests if total_requests > 0 else 0
            
            # Update average get time
            if metrics.avg_get_time == 0:
                metrics.avg_get_time = get_time
            else:
                metrics.avg_get_time = (metrics.avg_get_time + get_time) / 2
            
        except Exception as e:
            logger.error(f"Error updating hit metrics: {e}")
    
    def _update_miss_metrics(self, cache_id: str):
        """Update miss metrics"""
        try:
            metrics = self.cache_metrics.get(cache_id)
            if not metrics:
                return
            
            # Update miss rate
            total_requests = metrics.hit_count + metrics.miss_count + 1
            metrics.miss_count = getattr(metrics, 'miss_count', 0) + 1
            metrics.hit_rate = metrics.hit_count / total_requests if total_requests > 0 else 0
            metrics.miss_rate = metrics.miss_count / total_requests if total_requests > 0 else 0
            
        except Exception as e:
            logger.error(f"Error updating miss metrics: {e}")
    
    def _update_set_metrics(self, cache_id: str, set_time: float):
        """Update set metrics"""
        try:
            metrics = self.cache_metrics.get(cache_id)
            if not metrics:
                return
            
            # Update average set time
            if metrics.avg_set_time == 0:
                metrics.avg_set_time = set_time
            else:
                metrics.avg_set_time = (metrics.avg_set_time + set_time) / 2
            
        except Exception as e:
            logger.error(f"Error updating set metrics: {e}")
    
    def _update_error_metrics(self, cache_id: str, error: str):
        """Update error metrics"""
        try:
            metrics = self.cache_metrics.get(cache_id)
            if not metrics:
                return
            
            metrics.error_count += 1
            metrics.last_error = error
            
        except Exception as e:
            logger.error(f"Error updating error metrics: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Monitor all caches
                await self._monitor_all_caches()
                
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
        """Recovery loop for handling cache recovery"""
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
    
    async def _monitor_all_caches(self):
        """Monitor all caches"""
        try:
            for cache_id in list(self.caches.keys()):
                try:
                    await self._monitor_cache(cache_id)
                except Exception as e:
                    logger.error(f"Error monitoring cache {cache_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error monitoring all caches: {e}")
    
    async def _monitor_cache(self, cache_id: str):
        """Monitor a specific cache"""
        try:
            cache = self.caches.get(cache_id)
            config = self.cache_configs.get(cache_id)
            metrics = self.cache_metrics.get(cache_id)
            
            if not cache or not config or not metrics:
                return
            
            # Update key count and size
            metrics.key_count = len(cache['data'])
            metrics.size_bytes = sum(entry.size_bytes for entry in cache['data'].values())
            
            # Calculate memory usage (approximate)
            if config.max_memory_mb > 0:
                metrics.memory_usage = metrics.size_bytes / (config.max_memory_mb * 1024 * 1024)
            
            # Calculate eviction rate
            if metrics.key_count > 0:
                # Simulate eviction rate based on memory pressure
                metrics.eviction_rate = max(0, metrics.memory_usage - 0.8) * 2
            
            # Update health score
            metrics.health_score = self._calculate_health_score(metrics)
            
            # Check if recovery is needed
            if self._should_recover_cache(cache_id, metrics, config):
                await self._queue_recovery_action(cache_id, RecoveryAction.RESTART)
                
        except Exception as e:
            logger.error(f"Error monitoring cache {cache_id}: {e}")
    
    def _calculate_health_score(self, metrics: CacheMetrics) -> float:
        """Calculate cache health score"""
        try:
            score = 1.0
            
            # Penalize high error rate
            if metrics.error_count > 0:
                score -= min(metrics.error_count * 0.1, 0.5)
            
            # Penalize high memory usage
            if metrics.memory_usage > 0.8:
                score -= (metrics.memory_usage - 0.8) * 2
            
            # Penalize low hit rate
            if metrics.hit_rate < 0.5:
                score -= (0.5 - metrics.hit_rate)
            
            # Penalize high eviction rate
            if metrics.eviction_rate > 0.1:
                score -= min(metrics.eviction_rate, 0.3)
            
            # Ensure score is between 0 and 1
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
            return 0.0
    
    def _should_recover_cache(self, cache_id: str, metrics: CacheMetrics, config: CacheConfig) -> bool:
        """Check if cache needs recovery"""
        try:
            # Check if cache is in failed state
            if metrics.status == CacheStatus.FAILED:
                return True
            
            # Check error rate
            if metrics.error_count > 10:
                return True
            
            # Check health score
            if metrics.health_score < 0.3:
                return True
            
            # Check memory usage
            if metrics.memory_usage > config.max_memory_usage:
                return True
            
            # Check if auto recovery is enabled
            if not config.auto_recovery:
                return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking recovery need: {e}")
            return False
    
    async def _queue_recovery_action(self, cache_id: str, action: RecoveryAction):
        """Queue a recovery action"""
        try:
            recovery_action = {
                'cache_id': cache_id,
                'action': action,
                'timestamp': datetime.utcnow()
            }
            
            await self.recovery_queue.put(recovery_action)
            
            logger.info(f"Queued recovery action: {action.value} for cache {cache_id}")
            
        except Exception as e:
            logger.error(f"Error queuing recovery action: {e}")
    
    async def _process_recovery_action(self, recovery_action: Dict[str, Any]):
        """Process a recovery action"""
        try:
            cache_id = recovery_action['cache_id']
            action = recovery_action['action']
            
            logger.info(f"Processing recovery action: {action.value} for cache {cache_id}")
            
            if action == RecoveryAction.RESTART:
                success = await self._restart_cache(cache_id)
            elif action == RecoveryAction.REBUILD:
                success = await self._rebuild_cache(cache_id)
            elif action == RecoveryAction.RESTORE:
                success = await self._restore_cache(cache_id)
            elif action == RecoveryAction.FAILOVER:
                success = await self._failover_cache(cache_id)
            elif action == RecoveryAction.CLEAR:
                success = await self.clear(cache_id)
            elif action == RecoveryAction.VALIDATE:
                success = await self._validate_cache(cache_id)
            else:
                logger.warning(f"Unknown recovery action: {action.value}")
                success = False
            
            # Update statistics
            self.recovery_stats['total_recoveries'] += 1
            if success:
                self.recovery_stats['successful_recoveries'] += 1
                logger.info(f"Successfully recovered cache {cache_id}")
            else:
                self.recovery_stats['failed_recoveries'] += 1
                logger.error(f"Failed to recover cache {cache_id}")
                
        except Exception as e:
            logger.error(f"Error processing recovery action: {e}")
    
    async def _restart_cache(self, cache_id: str) -> bool:
        """Restart cache"""
        try:
            logger.info(f"Restarting cache {cache_id}")
            
            # Clear cache data
            cache = self.caches.get(cache_id)
            if cache:
                cache['data'].clear()
            
            # Reset metrics
            metrics = self.cache_metrics.get(cache_id)
            if metrics:
                metrics.status = CacheStatus.RECOVERING
                metrics.last_recovery = datetime.utcnow()
                metrics.recovery_count += 1
            
            # Restore from backup if available
            if self.cache_configs[cache_id].backup_enabled:
                await self._restore_from_backup(cache_id)
            
            # Update status
            if metrics:
                metrics.status = CacheStatus.HEALTHY
            
            return True
            
        except Exception as e:
            logger.error(f"Error restarting cache {cache_id}: {e}")
            return False
    
    async def _rebuild_cache(self, cache_id: str) -> bool:
        """Rebuild cache"""
        try:
            logger.info(f"Rebuilding cache {cache_id}")
            
            # Clear cache
            await self.clear(cache_id)
            
            # Rebuild from data source (simulated)
            # In a real implementation, this would rebuild from primary data source
            await asyncio.sleep(1)
            
            return True
            
        except Exception as e:
            logger.error(f"Error rebuilding cache {cache_id}: {e}")
            return False
    
    async def _restore_cache(self, cache_id: str) -> bool:
        """Restore cache from backup"""
        try:
            logger.info(f"Restoring cache {cache_id}")
            
            cache = self.caches.get(cache_id)
            if not cache:
                return False
            
            # Restore from backup
            backup = cache['backup'].get('full_backup')
            if backup:
                cache['data'] = dict(backup['data'])
                logger.info(f"Restored {len(cache['data'])} entries from backup")
                return True
            else:
                logger.warning(f"No backup found for cache {cache_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error restoring cache {cache_id}: {e}")
            return False
    
    async def _restore_from_backup(self, cache_id: str):
        """Restore cache from backup entries"""
        try:
            cache = self.caches.get(cache_id)
            if not cache:
                return
            
            backup = cache['backup']
            if not backup:
                return
            
            # Restore individual entries
            restored_count = 0
            for key, backup_data in list(backup.items()):
                if key != 'full_backup' and isinstance(backup_data, dict):
                    entry_backup = backup_data.get('entry')
                    if entry_backup:
                        cache['data'][key] = entry_backup
                        restored_count += 1
            
            logger.info(f"Restored {restored_count} entries from backup for cache {cache_id}")
            
        except Exception as e:
            logger.error(f"Error restoring from backup: {e}")
    
    async def _failover_cache(self, cache_id: str) -> bool:
        """Failover cache to alternative"""
        try:
            logger.info(f"Failing over cache {cache_id}")
            
            # In a real implementation, this would switch to alternative cache
            # For now, we'll simulate the failover
            await asyncio.sleep(2)
            
            return True
            
        except Exception as e:
            logger.error(f"Error failing over cache {cache_id}: {e}")
            return False
    
    async def _validate_cache(self, cache_id: str) -> bool:
        """Validate cache data integrity"""
        try:
            logger.info(f"Validating cache {cache_id}")
            
            cache = self.caches.get(cache_id)
            if not cache:
                return False
            
            # Validate entries
            invalid_entries = []
            for key, entry in cache['data'].items():
                try:
                    # Validate checksum
                    serialized_value = entry.value
                    if entry.compressed:
                        serialized_value = gzip.decompress(serialized_value).decode('utf-8')
                    
                    checksum = hashlib.md5(str(serialized_value).encode('utf-8')).hexdigest()
                    if checksum != entry.checksum:
                        invalid_entries.append(key)
                        
                except Exception as e:
                    logger.error(f"Error validating entry {key}: {e}")
                    invalid_entries.append(key)
            
            # Remove invalid entries
            for key in invalid_entries:
                del cache['data'][key]
                self.recovery_stats['validation_failures'] += 1
            
            if invalid_entries:
                logger.warning(f"Removed {len(invalid_entries)} invalid entries from cache {cache_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating cache {cache_id}: {e}")
            return False
    
    async def _check_recovery_actions(self):
        """Check for pending recovery actions"""
        try:
            # This would check for any additional recovery conditions
            # For now, we'll just log the current status
            total_caches = len(self.caches)
            healthy_caches = sum(1 for metrics in self.cache_metrics.values() if metrics.health_score > 0.7)
            failed_caches = sum(1 for metrics in self.cache_metrics.values() if metrics.status == CacheStatus.FAILED)
            
            logger.info(f"Cache status: {healthy_caches} healthy, {failed_caches} failed out of {total_caches} total")
            
        except Exception as e:
            logger.error(f"Error checking recovery actions: {e}")
    
    async def _update_statistics(self):
        """Update recovery statistics"""
        try:
            # Update cache counts
            total_caches = len(self.caches)
            healthy_caches = sum(1 for metrics in self.cache_metrics.values() if metrics.health_score > 0.7)
            failed_caches = sum(1 for metrics in self.cache_metrics.values() if metrics.status == CacheStatus.FAILED)
            
            logger.info(f"Cache statistics: {healthy_caches} healthy, {failed_caches} failed out of {total_caches} total")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def get_cache_metrics(self, cache_id: str) -> Optional[CacheMetrics]:
        """Get metrics for a specific cache"""
        try:
            return self.cache_metrics.get(cache_id)
        except Exception as e:
            logger.error(f"Error getting cache metrics: {e}")
            return None
    
    async def get_all_cache_metrics(self) -> Dict[str, CacheMetrics]:
        """Get metrics for all caches"""
        try:
            return dict(self.cache_metrics)
        except Exception as e:
            logger.error(f"Error getting all cache metrics: {e}")
            return {}
    
    async def get_recovery_statistics(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        try:
            stats = self.recovery_stats.copy()
            
            # Add cache counts
            total_caches = len(self.caches)
            healthy_caches = sum(1 for metrics in self.cache_metrics.values() if metrics.health_score > 0.7)
            
            stats.update({
                'total_caches': total_caches,
                'healthy_caches': healthy_caches,
                'health_percentage': (healthy_caches / total_caches * 100) if total_caches > 0 else 0
            })
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting recovery statistics: {e}")
            return {'error': str(e)}


# Global cache recovery system instance
cache_recovery_system = CacheRecoverySystem()


async def get_cache_status(cache_id: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific cache"""
    try:
        metrics = await cache_recovery_system.get_cache_metrics(cache_id)
        if metrics:
            return {
                'cache_id': metrics.cache_id,
                'cache_type': metrics.cache_type.value,
                'status': metrics.status.value,
                'hit_rate': metrics.hit_rate,
                'memory_usage': metrics.memory_usage,
                'key_count': metrics.key_count,
                'health_score': metrics.health_score,
                'error_count': metrics.error_count,
                'recovery_count': metrics.recovery_count
            }
        return None
    except Exception as e:
        logger.error(f"Error getting cache status: {e}")
        return None


async def get_all_cache_status() -> Dict[str, Any]:
    """Get status of all caches"""
    try:
        metrics = await cache_recovery_system.get_all_cache_metrics()
        return {
            cache_id: {
                'cache_id': metrics.cache_id,
                'cache_type': metrics.cache_type.value,
                'status': metrics.status.value,
                'hit_rate': metrics.hit_rate,
                'memory_usage': metrics.memory_usage,
                'key_count': metrics.key_count,
                'health_score': metrics.health_score,
                'error_count': metrics.error_count,
                'recovery_count': metrics.recovery_count
            }
            for cache_id, metrics in metrics.items()
        }
    except Exception as e:
        logger.error(f"Error getting all cache status: {e}")
        return {}


async def register_cache(cache_id: str, cache_type: str, config: Optional[Dict[str, Any]] = None) -> str:
    """Register a new cache"""
    try:
        # Convert strings to enums
        cache_type_enum = CacheType(cache_type)
        
        # Convert config dict to CacheConfig
        cache_config = None
        if config:
            cache_config = CacheConfig(
                cache_id=cache_id,
                cache_type=cache_type_enum,
                max_memory_mb=config.get('max_memory_mb', 512),
                max_keys=config.get('max_keys', 100000),
                ttl_seconds=config.get('ttl_seconds', 3600),
                cleanup_interval=config.get('cleanup_interval', 300),
                health_check_interval=config.get('health_check_interval', 60),
                max_error_rate=config.get('max_error_rate', 0.05),
                max_memory_usage=config.get('max_memory_usage', 0.8),
                auto_recovery=config.get('auto_recovery', True),
                backup_enabled=config.get('backup_enabled', True),
                validation_enabled=config.get('validation_enabled', True),
                compression_enabled=config.get('compression_enabled', True)
            )
        
        # Register cache
        success = await cache_recovery_system.register_cache(cache_id, cache_type_enum, cache_config)
        
        if success:
            return f"Cache {cache_id} registered successfully"
        else:
            return f"Failed to register cache {cache_id}"
            
    except Exception as e:
        logger.error(f"Error registering cache: {e}")
        return f"Error registering cache: {e}"


async def get_cache_statistics() -> Dict[str, Any]:
    """Get cache recovery statistics"""
    try:
        return await cache_recovery_system.get_recovery_statistics()
    except Exception as e:
        logger.error(f"Error getting cache statistics: {e}")
        return {'error': str(e)}


# Initialize cache recovery system
async def initialize_cache_recovery():
    """Initialize cache recovery system"""
    try:
        await cache_recovery_system.start()
        logger.info("Cache recovery system initialized")
        return "Cache recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing cache recovery system: {e}")
        return f"Error initializing cache recovery system: {e}"


# Cleanup function
async def cleanup_cache_recovery():
    """Cleanup cache recovery system"""
    try:
        await cache_recovery_system.stop()
        logger.info("Cache recovery system cleaned up")
        return "Cache recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up cache recovery system: {e}")
        return f"Error cleaning up cache recovery system: {e}"
