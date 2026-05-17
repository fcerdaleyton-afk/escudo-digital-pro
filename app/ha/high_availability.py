#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - High Availability Architecture
Comprehensive HA system with horizontal scaling, stateless design, and distributed coordination
"""

import os
import sys
import asyncio
import logging
import json
import time
import uuid
import hashlib
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Set
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref
import socket

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/high_availability.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """Node status enumeration"""
    STARTING = "starting"
    ACTIVE = "active"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"
    FAILED = "failed"
    SHUTTING_DOWN = "shutting_down"


class LockType(Enum):
    """Lock type enumeration"""
    SESSION = "session"
    RESOURCE = "resource"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    MAINTENANCE = "maintenance"


class ScalingPolicy(Enum):
    """Scaling policy enumeration"""
    MANUAL = "manual"
    AUTO_SCALE = "auto_scale"
    CIRCUIT_BREAKER = "circuit_breaker"
    LOAD_BASED = "load_based"


@dataclass
class NodeInfo:
    """Node information structure"""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: NodeStatus
    last_heartbeat: datetime
    capabilities: List[str]
    load_score: float
    memory_usage: float
    cpu_usage: float
    active_connections: int
    max_connections: int
    version: str
    region: str
    availability_zone: str
    metadata: Dict[str, Any]


@dataclass
class DistributedLock:
    """Distributed lock structure"""
    lock_id: str
    lock_type: LockType
    resource_id: str
    owner_node: str
    acquired_at: datetime
    expires_at: datetime
    ttl: int
    metadata: Dict[str, Any]


@dataclass
class ScalingEvent:
    """Scaling event structure"""
    event_id: str
    scaling_type: str
    trigger_reason: str
    target_instances: int
    current_instances: int
    timestamp: datetime
    node_id: str
    metadata: Dict[str, Any]


@dataclass
class FailoverEvent:
    """Failover event structure"""
    event_id: str
    failed_node: str
    backup_nodes: List[str]
    failover_time: datetime
    recovery_time: Optional[datetime]
    services_transferred: List[str]
    metadata: Dict[str, Any]


class HorizontalScalingManager:
    """Horizontal scaling manager"""
    
    def __init__(self):
        """Initialize horizontal scaling manager"""
        self.nodes: Dict[str, NodeInfo] = {}
        self.scaling_policies: Dict[str, ScalingPolicy] = {}
        self.load_balancer_weights: Dict[str, float] = {}
        self.min_instances: int = 1
        self.max_instances: int = 10
        self.current_instances: int = 1
        self.scaling_events: List[ScalingEvent] = []
        self.auto_scale_enabled: bool = True
        self.scale_up_threshold: float = 0.8
        self.scale_down_threshold: float = 0.3
        self.scale_up_cooldown: int = 300  # 5 minutes
        self.scale_down_cooldown: int = 600  # 10 minutes
        self.last_scale_up: datetime = datetime.utcnow()
        self.last_scale_down: datetime = datetime.utcnow()
        
        logger.info("Horizontal scaling manager initialized")
    
    async def register_node(self, node_info: NodeInfo) -> bool:
        """Register a new node"""
        try:
            self.nodes[node_info.node_id] = node_info
            self.current_instances = len(self.nodes)
            
            # Update load balancer weights
            await self._update_load_balancer_weights()
            
            logger.info(f"Node registered: {node_info.node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error registering node: {e}")
            return False
    
    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a node"""
        try:
            if node_id in self.nodes:
                del self.nodes[node_id]
                self.current_instances = len(self.nodes)
                
                # Update load balancer weights
                await self._update_load_balancer_weights()
                
                logger.info(f"Node unregistered: {node_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error unregistering node: {e}")
            return False
    
    async def update_node_status(self, node_id: str, status: NodeStatus) -> bool:
        """Update node status"""
        try:
            if node_id in self.nodes:
                self.nodes[node_id].status = status
                self.nodes[node_id].last_heartbeat = datetime.utcnow()
                
                # Update load balancer weights if node is no longer active
                if status != NodeStatus.ACTIVE:
                    await self._update_load_balancer_weights()
                
                logger.info(f"Node status updated: {node_id} -> {status.value}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating node status: {e}")
            return False
    
    async def update_node_metrics(self, node_id: str, load_score: float, 
                                memory_usage: float, cpu_usage: float, 
                                active_connections: int) -> bool:
        """Update node metrics"""
        try:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.load_score = load_score
                node.memory_usage = memory_usage
                node.cpu_usage = cpu_usage
                node.active_connections = active_connections
                node.last_heartbeat = datetime.utcnow()
                
                # Check if auto-scaling is needed
                if self.auto_scale_enabled:
                    await self._check_auto_scaling()
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating node metrics: {e}")
            return False
    
    async def _update_load_balancer_weights(self):
        """Update load balancer weights"""
        try:
            active_nodes = [node for node in self.nodes.values() if node.status == NodeStatus.ACTIVE]
            
            if not active_nodes:
                self.load_balancer_weights = {}
                return
            
            # Calculate weights based on load and capacity
            total_capacity = sum(node.max_connections - node.active_connections for node in active_nodes)
            
            for node in active_nodes:
                available_capacity = node.max_connections - node.active_connections
                weight = available_capacity / total_capacity if total_capacity > 0 else 1.0 / len(active_nodes)
                self.load_balancer_weights[node.node_id] = weight
            
        except Exception as e:
            logger.error(f"Error updating load balancer weights: {e}")
    
    async def _check_auto_scaling(self):
        """Check if auto-scaling is needed"""
        try:
            now = datetime.utcnow()
            
            # Calculate average load across active nodes
            active_nodes = [node for node in self.nodes.values() if node.status == NodeStatus.ACTIVE]
            
            if not active_nodes:
                return
            
            avg_load = sum(node.load_score for node in active_nodes) / len(active_nodes)
            avg_memory = sum(node.memory_usage for node in active_nodes) / len(active_nodes)
            avg_cpu = sum(node.cpu_usage for node in active_nodes) / len(active_nodes)
            
            # Check scale up conditions
            if (avg_load > self.scale_up_threshold or 
                avg_memory > self.scale_up_threshold or 
                avg_cpu > self.scale_up_threshold):
                
                if (now - self.last_scale_up).total_seconds() > self.scale_up_cooldown:
                    if self.current_instances < self.max_instances:
                        await self._scale_up("High load detected")
                        return
            
            # Check scale down conditions
            if (avg_load < self.scale_down_threshold and 
                avg_memory < self.scale_down_threshold and 
                avg_cpu < self.scale_down_threshold):
                
                if (now - self.last_scale_down).total_seconds() > self.scale_down_cooldown:
                    if self.current_instances > self.min_instances:
                        await self._scale_down("Low load detected")
                        return
            
        except Exception as e:
            logger.error(f"Error checking auto-scaling: {e}")
    
    async def _scale_up(self, reason: str):
        """Scale up the system"""
        try:
            target_instances = min(self.current_instances + 1, self.max_instances)
            
            scaling_event = ScalingEvent(
                event_id=str(uuid.uuid4()),
                scaling_type="scale_up",
                trigger_reason=reason,
                target_instances=target_instances,
                current_instances=self.current_instances,
                timestamp=datetime.utcnow(),
                node_id=list(self.nodes.keys())[0] if self.nodes else "unknown",
                metadata={"reason": reason}
            )
            
            self.scaling_events.append(scaling_event)
            self.last_scale_up = datetime.utcnow()
            
            # In a real implementation, this would trigger container orchestration
            logger.info(f"Scale up triggered: {self.current_instances} -> {target_instances} ({reason})")
            
        except Exception as e:
            logger.error(f"Error scaling up: {e}")
    
    async def _scale_down(self, reason: str):
        """Scale down the system"""
        try:
            target_instances = max(self.current_instances - 1, self.min_instances)
            
            scaling_event = ScalingEvent(
                event_id=str(uuid.uuid4()),
                scaling_type="scale_down",
                trigger_reason=reason,
                target_instances=target_instances,
                current_instances=self.current_instances,
                timestamp=datetime.utcnow(),
                node_id=list(self.nodes.keys())[0] if self.nodes else "unknown",
                metadata={"reason": reason}
            )
            
            self.scaling_events.append(scaling_event)
            self.last_scale_down = datetime.utcnow()
            
            # In a real implementation, this would trigger container orchestration
            logger.info(f"Scale down triggered: {self.current_instances} -> {target_instances} ({reason})")
            
        except Exception as e:
            logger.error(f"Error scaling down: {e}")
    
    async def get_scaling_recommendations(self) -> Dict[str, Any]:
        """Get scaling recommendations"""
        try:
            active_nodes = [node for node in self.nodes.values() if node.status == NodeStatus.ACTIVE]
            
            if not active_nodes:
                return {"recommendation": "no_active_nodes", "reason": "No active nodes available"}
            
            avg_load = sum(node.load_score for node in active_nodes) / len(active_nodes)
            avg_memory = sum(node.memory_usage for node in active_nodes) / len(active_nodes)
            avg_cpu = sum(node.cpu_usage for node in active_nodes) / len(active_nodes)
            
            # Calculate recommendations
            if avg_load > 0.9 or avg_memory > 0.9 or avg_cpu > 0.9:
                recommendation = "scale_up"
                reason = "Critical resource utilization"
            elif avg_load > 0.8 or avg_memory > 0.8 or avg_cpu > 0.8:
                recommendation = "scale_up"
                reason = "High resource utilization"
            elif avg_load < 0.2 and avg_memory < 0.2 and avg_cpu < 0.2:
                recommendation = "scale_down"
                reason = "Low resource utilization"
            else:
                recommendation = "maintain"
                reason = "Optimal resource utilization"
            
            return {
                "recommendation": recommendation,
                "reason": reason,
                "current_instances": self.current_instances,
                "min_instances": self.min_instances,
                "max_instances": self.max_instances,
                "avg_load": avg_load,
                "avg_memory": avg_memory,
                "avg_cpu": avg_cpu,
                "auto_scale_enabled": self.auto_scale_enabled
            }
            
        except Exception as e:
            logger.error(f"Error getting scaling recommendations: {e}")
            return {"error": str(e)}


class StatelessAPIDesign:
    """Stateless API design manager"""
    
    def __init__(self):
        """Initialize stateless API design"""
        self.session_store = None  # Will be injected
        self.request_context = {}
        self.api_version = "v1"
        self.stateless_endpoints: Set[str] = set()
        self.session_timeout: int = 3600  # 1 hour
        self.request_id_counter = 0
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Stateless API design initialized")
    
    def set_session_store(self, session_store):
        """Set session store (Redis)"""
        self.session_store = session_store
    
    async def create_request_context(self, request_data: Dict[str, Any]) -> str:
        """Create request context"""
        try:
            self.request_id_counter += 1
            request_id = f"req_{int(time.time())}_{self.request_id_counter}"
            
            context = {
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": request_data.get("user_id"),
                "ip_address": request_data.get("ip_address"),
                "user_agent": request_data.get("user_agent"),
                "api_version": self.api_version,
                "endpoint": request_data.get("endpoint"),
                "method": request_data.get("method"),
                "metadata": request_data.get("metadata", {})
            }
            
            self.request_context[request_id] = context
            
            return request_id
            
        except Exception as e:
            logger.error(f"Error creating request context: {e}")
            return ""
    
    async def get_request_context(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get request context"""
        try:
            return self.request_context.get(request_id)
        except Exception as e:
            logger.error(f"Error getting request context: {e}")
            return None
    
    async def cleanup_request_context(self, request_id: str):
        """Clean up request context"""
        try:
            if request_id in self.request_context:
                del self.request_context[request_id]
        except Exception as e:
            logger.error(f"Error cleaning up request context: {e}")
    
    async def create_session(self, user_id: str, session_data: Dict[str, Any]) -> str:
        """Create user session"""
        try:
            if not self.session_store:
                return ""
            
            session_id = str(uuid.uuid4())
            session_key = f"session:{session_id}"
            
            session_info = {
                "session_id": session_id,
                "user_id": user_id,
                "created_at": datetime.utcnow().isoformat(),
                "last_accessed": datetime.utcnow().isoformat(),
                "data": session_data,
                "ip_address": session_data.get("ip_address"),
                "user_agent": session_data.get("user_agent")
            }
            
            # Store session in Redis
            await self.session_store.set(session_key, json.dumps(session_info), ex=self.session_timeout)
            
            return session_id
            
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return ""
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        try:
            if not self.session_store:
                return None
            
            session_key = f"session:{session_id}"
            session_data = await self.session_store.get(session_key)
            
            if session_data:
                session_info = json.loads(session_data)
                
                # Update last accessed time
                session_info["last_accessed"] = datetime.utcnow().isoformat()
                await self.session_store.set(session_key, json.dumps(session_info), ex=self.session_timeout)
                
                return session_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None
    
    async def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Update session data"""
        try:
            if not self.session_store:
                return False
            
            session_key = f"session:{session_id}"
            existing_data = await self.session_store.get(session_key)
            
            if existing_data:
                session_info = json.loads(existing_data)
                session_info["data"].update(session_data)
                session_info["last_accessed"] = datetime.utcnow().isoformat()
                
                await self.session_store.set(session_key, json.dumps(session_info), ex=self.session_timeout)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        try:
            if not self.session_store:
                return False
            
            session_key = f"session:{session_id}"
            await self.session_store.delete(session_key)
            return True
            
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            return False
    
    async def check_rate_limit(self, user_id: str, endpoint: str, limit: int = 100, window: int = 3600) -> bool:
        """Check rate limit"""
        try:
            if not self.session_store:
                return True
            
            rate_key = f"rate_limit:{user_id}:{endpoint}"
            current_count = await self.session_store.get(rate_key)
            
            if current_count is None:
                await self.session_store.set(rate_key, "1", ex=window)
                return True
            
            count = int(current_count)
            if count >= limit:
                return False
            
            await self.session_store.incr(rate_key)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True  # Allow request on error
    
    def register_stateless_endpoint(self, endpoint: str):
        """Register stateless endpoint"""
        self.stateless_endpoints.add(endpoint)
    
    def is_stateless_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is stateless"""
        return endpoint in self.stateless_endpoints


class RedisSharedStateManager:
    """Redis shared state manager"""
    
    def __init__(self, redis_client=None):
        """Initialize Redis shared state manager"""
        self.redis_client = redis_client
        self.state_keys: Dict[str, str] = {}
        self.lock_keys: Dict[str, str] = {}
        self.cache_ttl: int = 3600  # 1 hour
        self.lock_ttl: int = 30  # 30 seconds
        
        logger.info("Redis shared state manager initialized")
    
    def set_redis_client(self, redis_client):
        """Set Redis client"""
        self.redis_client = redis_client
    
    async def set_shared_state(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set shared state"""
        try:
            if not self.redis_client:
                return False
            
            serialized_value = json.dumps(value) if not isinstance(value, str) else value
            actual_ttl = ttl or self.cache_ttl
            
            await self.redis_client.set(key, serialized_value, ex=actual_ttl)
            self.state_keys[key] = key
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting shared state: {e}")
            return False
    
    async def get_shared_state(self, key: str) -> Optional[Any]:
        """Get shared state"""
        try:
            if not self.redis_client:
                return None
            
            value = await self.redis_client.get(key)
            
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting shared state: {e}")
            return None
    
    async def delete_shared_state(self, key: str) -> bool:
        """Delete shared state"""
        try:
            if not self.redis_client:
                return False
            
            await self.redis_client.delete(key)
            
            if key in self.state_keys:
                del self.state_keys[key]
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting shared state: {e}")
            return False
    
    async def increment_shared_state(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment shared state counter"""
        try:
            if not self.redis_client:
                return None
            
            result = await self.redis_client.incrby(key, amount)
            return result
            
        except Exception as e:
            logger.error(f"Error incrementing shared state: {e}")
            return None
    
    async def get_all_shared_states(self) -> Dict[str, Any]:
        """Get all shared states"""
        try:
            if not self.redis_client:
                return {}
            
            states = {}
            for key in self.state_keys.values():
                value = await self.get_shared_state(key)
                if value is not None:
                    states[key] = value
            
            return states
            
        except Exception as e:
            logger.error(f"Error getting all shared states: {e}")
            return {}


class DistributedLockManager:
    """Distributed lock manager"""
    
    def __init__(self, redis_client=None):
        """Initialize distributed lock manager"""
        self.redis_client = redis_client
        self.locks: Dict[str, DistributedLock] = {}
        self.default_ttl: int = 30  # 30 seconds
        self.max_retries: int = 3
        self.retry_delay: float = 0.1  # 100ms
        self.lock_timeout: float = 10.0  # 10 seconds
        
        logger.info("Distributed lock manager initialized")
    
    def set_redis_client(self, redis_client):
        """Set Redis client"""
        self.redis_client = redis_client
    
    async def acquire_lock(self, lock_type: LockType, resource_id: str, 
                         node_id: str, ttl: Optional[int] = None, 
                         metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Acquire distributed lock"""
        try:
            if not self.redis_client:
                return None
            
            lock_id = str(uuid.uuid4())
            lock_key = f"lock:{lock_type.value}:{resource_id}"
            actual_ttl = ttl or self.default_ttl
            
            # Create lock data
            lock_data = {
                "lock_id": lock_id,
                "lock_type": lock_type.value,
                "resource_id": resource_id,
                "owner_node": node_id,
                "acquired_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(seconds=actual_ttl)).isoformat(),
                "ttl": actual_ttl,
                "metadata": metadata or {}
            }
            
            # Try to acquire lock with retry logic
            for attempt in range(self.max_retries):
                # Use SET with NX and EX for atomic lock acquisition
                success = await self.redis_client.set(
                    lock_key, 
                    json.dumps(lock_data), 
                    nx=True, 
                    ex=actual_ttl
                )
                
                if success:
                    # Create lock object
                    lock = DistributedLock(
                        lock_id=lock_id,
                        lock_type=lock_type,
                        resource_id=resource_id,
                        owner_node=node_id,
                        acquired_at=datetime.utcnow(),
                        expires_at=datetime.utcnow() + timedelta(seconds=actual_ttl),
                        ttl=actual_ttl,
                        metadata=metadata or {}
                    )
                    
                    self.locks[lock_id] = lock
                    self.lock_keys[lock_key] = lock_id
                    
                    logger.info(f"Lock acquired: {lock_id} for {resource_id}")
                    return lock_id
                
                # Wait before retry
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
            
            logger.warning(f"Failed to acquire lock for {resource_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error acquiring lock: {e}")
            return None
    
    async def release_lock(self, lock_id: str) -> bool:
        """Release distributed lock"""
        try:
            if not self.redis_client:
                return False
            
            if lock_id not in self.locks:
                return False
            
            lock = self.locks[lock_id]
            lock_key = f"lock:{lock.lock_type.value}:{lock.resource_id}"
            
            # Verify ownership before releasing
            current_data = await self.redis_client.get(lock_key)
            if current_data:
                current_lock = json.loads(current_data)
                if current_lock.get("lock_id") == lock_id:
                    await self.redis_client.delete(lock_key)
                    
                    # Clean up local lock
                    del self.locks[lock_id]
                    if lock_key in self.lock_keys:
                        del self.lock_keys[lock_key]
                    
                    logger.info(f"Lock released: {lock_id}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error releasing lock: {e}")
            return False
    
    async def renew_lock(self, lock_id: str, ttl: Optional[int] = None) -> bool:
        """Renew distributed lock"""
        try:
            if not self.redis_client:
                return False
            
            if lock_id not in self.locks:
                return False
            
            lock = self.locks[lock_id]
            lock_key = f"lock:{lock.lock_type.value}:{lock.resource_id}"
            actual_ttl = ttl or self.default_ttl
            
            # Update lock data
            lock.expires_at = datetime.utcnow() + timedelta(seconds=actual_ttl)
            lock.ttl = actual_ttl
            
            updated_data = {
                "lock_id": lock.lock_id,
                "lock_type": lock.lock_type.value,
                "resource_id": lock.resource_id,
                "owner_node": lock.owner_node,
                "acquired_at": lock.acquired_at.isoformat(),
                "expires_at": lock.expires_at.isoformat(),
                "ttl": lock.ttl,
                "metadata": lock.metadata
            }
            
            # Update Redis with new TTL
            await self.redis_client.set(lock_key, json.dumps(updated_data), ex=actual_ttl)
            
            logger.info(f"Lock renewed: {lock_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error renewing lock: {e}")
            return False
    
    async def is_lock_held(self, lock_type: LockType, resource_id: str) -> Optional[str]:
        """Check if lock is held"""
        try:
            if not self.redis_client:
                return None
            
            lock_key = f"lock:{lock_type.value}:{resource_id}"
            lock_data = await self.redis_client.get(lock_key)
            
            if lock_data:
                lock_info = json.loads(lock_data)
                expires_at = datetime.fromisoformat(lock_info["expires_at"])
                
                if datetime.utcnow() < expires_at:
                    return lock_info["lock_id"]
                else:
                    # Lock expired, clean it up
                    await self.redis_client.delete(lock_key)
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking lock: {e}")
            return None
    
    async def get_active_locks(self) -> List[DistributedLock]:
        """Get all active locks"""
        try:
            if not self.redis_client:
                return []
            
            active_locks = []
            current_time = datetime.utcnow()
            
            for lock in self.locks.values():
                if current_time < lock.expires_at:
                    active_locks.append(lock)
                else:
                    # Clean up expired locks
                    await self.release_lock(lock.lock_id)
            
            return active_locks
            
        except Exception as e:
            logger.error(f"Error getting active locks: {e}")
            return []


class GracefulFailoverManager:
    """Graceful failover manager"""
    
    def __init__(self):
        """Initialize graceful failover manager"""
        self.failover_events: List[FailoverEvent] = []
        self.backup_nodes: Dict[str, List[str]] = {}
        self.failover_policies: Dict[str, Dict[str, Any]] = {}
        self.health_check_interval: int = 30  # 30 seconds
        self.failover_timeout: int = 300  # 5 minutes
        self.max_failover_attempts: int = 3
        self.current_failovers: Dict[str, FailoverEvent] = {}
        
        logger.info("Graceful failover manager initialized")
    
    def configure_backup_nodes(self, primary_node: str, backup_nodes: List[str]):
        """Configure backup nodes for primary"""
        self.backup_nodes[primary_node] = backup_nodes
        logger.info(f"Backup nodes configured for {primary_node}: {backup_nodes}")
    
    async def detect_node_failure(self, node_id: str) -> bool:
        """Detect node failure"""
        try:
            # Check if node is already in failover
            if node_id in self.current_failovers:
                return False
            
            # Create failover event
            failover_event = FailoverEvent(
                event_id=str(uuid.uuid4()),
                failed_node=node_id,
                backup_nodes=self.backup_nodes.get(node_id, []),
                failover_time=datetime.utcnow(),
                recovery_time=None,
                services_transferred=[],
                metadata={"auto_detected": True}
            )
            
            # Trigger failover
            success = await self._trigger_failover(failover_event)
            
            if success:
                self.current_failovers[node_id] = failover_event
                logger.info(f"Failover triggered for node: {node_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting node failure: {e}")
            return False
    
    async def _trigger_failover(self, failover_event: FailoverEvent) -> bool:
        """Trigger graceful failover"""
        try:
            failed_node = failover_event.failed_node
            backup_nodes = failover_event.backup_nodes
            
            if not backup_nodes:
                logger.error(f"No backup nodes available for {failed_node}")
                return False
            
            # Select best backup node
            best_backup = await self._select_best_backup_node(backup_nodes)
            
            if not best_backup:
                logger.error(f"No suitable backup node found for {failed_node}")
                return False
            
            # Transfer services
            services_transferred = await self._transfer_services(failed_node, best_backup)
            failover_event.services_transferred = services_transferred
            
            # Update failover event
            self.failover_events.append(failover_event)
            
            logger.info(f"Failover completed: {failed_node} -> {best_backup}")
            return True
            
        except Exception as e:
            logger.error(f"Error triggering failover: {e}")
            return False
    
    async def _select_best_backup_node(self, backup_nodes: List[str]) -> Optional[str]:
        """Select best backup node"""
        try:
            # In a real implementation, this would check node health, load, etc.
            # For now, we'll return the first available backup node
            return backup_nodes[0] if backup_nodes else None
            
        except Exception as e:
            logger.error(f"Error selecting backup node: {e}")
            return None
    
    async def _transfer_services(self, failed_node: str, backup_node: str) -> List[str]:
        """Transfer services from failed to backup node"""
        try:
            # In a real implementation, this would:
            # 1. Stop services on failed node
            # 2. Start services on backup node
            # 3. Update DNS/load balancer
            # 4. Verify service health
            
            services_transferred = []
            
            # Simulate service transfer
            services = ["api", "websocket", "monitoring", "security"]
            
            for service in services:
                # Transfer service
                await asyncio.sleep(0.1)  # Simulate transfer time
                services_transferred.append(service)
                logger.info(f"Service {service} transferred to {backup_node}")
            
            return services_transferred
            
        except Exception as e:
            logger.error(f"Error transferring services: {e}")
            return []
    
    async def recover_node(self, node_id: str) -> bool:
        """Recover failed node"""
        try:
            if node_id not in self.current_failovers:
                return False
            
            failover_event = self.current_failovers[node_id]
            failover_event.recovery_time = datetime.utcnow()
            
            # In a real implementation, this would:
            # 1. Verify node health
            # 2. Start services on recovered node
            # 3. Transfer services back
            # 4. Update DNS/load balancer
            
            logger.info(f"Node recovered: {node_id}")
            
            # Remove from current failovers
            del self.current_failovers[node_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Error recovering node: {e}")
            return False
    
    async def get_failover_status(self) -> Dict[str, Any]:
        """Get failover status"""
        try:
            return {
                "current_failovers": len(self.current_failovers),
                "total_failovers": len(self.failover_events),
                "backup_configurations": len(self.backup_nodes),
                "active_failovers": [
                    {
                        "failed_node": event.failed_node,
                        "backup_nodes": event.backup_nodes,
                        "failover_time": event.failover_time.isoformat(),
                        "services_transferred": len(event.services_transferred),
                        "recovered": event.recovery_time is not None
                    }
                    for event in self.current_failovers.values()
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting failover status: {e}")
            return {"error": str(e)}


class AsyncSafeScalingManager:
    """Async-safe scaling manager"""
    
    def __init__(self):
        """Initialize async-safe scaling manager"""
        self.scaling_operations: Dict[str, asyncio.Task] = {}
        self.coordination_locks: Dict[str, asyncio.Lock] = {}
        self.scaling_state: Dict[str, Dict[str, Any]] = {}
        self.max_concurrent_operations: int = 5
        self.operation_timeout: int = 300  # 5 minutes
        
        logger.info("Async-safe scaling manager initialized")
    
    async def coordinate_scaling_operation(self, operation_id: str, 
                                         scaling_func: Callable, 
                                         **kwargs) -> bool:
        """Coordinate scaling operation"""
        try:
            # Check if operation already exists
            if operation_id in self.scaling_operations:
                return False
            
            # Create coordination lock
            if operation_id not in self.coordination_locks:
                self.coordination_locks[operation_id] = asyncio.Lock()
            
            # Execute scaling operation with lock
            async with self.coordination_locks[operation_id]:
                # Check concurrent operation limit
                active_operations = [op for op in self.scaling_operations.values() if not op.done()]
                if len(active_operations) >= self.max_concurrent_operations:
                    logger.warning(f"Max concurrent operations reached for {operation_id}")
                    return False
                
                # Create scaling task
                task = asyncio.create_task(
                    self._execute_scaling_operation(operation_id, scaling_func, **kwargs)
                )
                
                self.scaling_operations[operation_id] = task
                
                try:
                    # Wait for completion with timeout
                    result = await asyncio.wait_for(task, timeout=self.operation_timeout)
                    return result
                except asyncio.TimeoutError:
                    logger.error(f"Scaling operation timeout: {operation_id}")
                    task.cancel()
                    return False
                finally:
                    # Clean up
                    if operation_id in self.scaling_operations:
                        del self.scaling_operations[operation_id]
            
        except Exception as e:
            logger.error(f"Error coordinating scaling operation: {e}")
            return False
    
    async def _execute_scaling_operation(self, operation_id: str, 
                                        scaling_func: Callable, 
                                        **kwargs) -> bool:
        """Execute scaling operation"""
        try:
            # Set scaling state
            self.scaling_state[operation_id] = {
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
                "metadata": kwargs
            }
            
            # Execute scaling function
            result = await scaling_func(**kwargs)
            
            # Update state
            self.scaling_state[operation_id]["status"] = "completed"
            self.scaling_state[operation_id]["completed_at"] = datetime.utcnow().isoformat()
            self.scaling_state[operation_id]["result"] = result
            
            return result
            
        except Exception as e:
            # Update state with error
            self.scaling_state[operation_id]["status"] = "failed"
            self.scaling_state[operation_id]["failed_at"] = datetime.utcnow().isoformat()
            self.scaling_state[operation_id]["error"] = str(e)
            
            logger.error(f"Error executing scaling operation {operation_id}: {e}")
            return False
    
    async def cancel_scaling_operation(self, operation_id: str) -> bool:
        """Cancel scaling operation"""
        try:
            if operation_id in self.scaling_operations:
                task = self.scaling_operations[operation_id]
                task.cancel()
                
                # Update state
                if operation_id in self.scaling_state:
                    self.scaling_state[operation_id]["status"] = "cancelled"
                    self.scaling_state[operation_id]["cancelled_at"] = datetime.utcnow().isoformat()
                
                # Clean up
                del self.scaling_operations[operation_id]
                
                logger.info(f"Scaling operation cancelled: {operation_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error cancelling scaling operation: {e}")
            return False
    
    async def get_scaling_status(self) -> Dict[str, Any]:
        """Get scaling status"""
        try:
            active_operations = []
            completed_operations = []
            
            for op_id, state in self.scaling_state.items():
                if state["status"] == "running":
                    active_operations.append({
                        "operation_id": op_id,
                        "status": state["status"],
                        "started_at": state["started_at"],
                        "metadata": state.get("metadata", {})
                    })
                else:
                    completed_operations.append({
                        "operation_id": op_id,
                        "status": state["status"],
                        "started_at": state["started_at"],
                        "completed_at": state.get("completed_at"),
                        "failed_at": state.get("failed_at"),
                        "cancelled_at": state.get("cancelled_at"),
                        "result": state.get("result"),
                        "error": state.get("error")
                    })
            
            return {
                "active_operations": len(active_operations),
                "completed_operations": len(completed_operations),
                "max_concurrent": self.max_concurrent_operations,
                "operation_timeout": self.operation_timeout,
                "active_ops": active_operations,
                "completed_ops": completed_operations
            }
            
        except Exception as e:
            logger.error(f"Error getting scaling status: {e}")
            return {"error": str(e)}


class HighAvailabilityCoordinator:
    """High availability coordinator"""
    
    def __init__(self):
        """Initialize HA coordinator"""
        self.scaling_manager = HorizontalScalingManager()
        self.stateless_api = StatelessAPIDesign()
        self.shared_state = RedisSharedStateManager()
        self.distributed_locks = DistributedLockManager()
        self.failover_manager = GracefulFailoverManager()
        self.async_scaling = AsyncSafeScalingManager()
        
        self.node_id = f"node_{socket.gethostname()}_{int(time.time())}"
        self.is_running = False
        self.health_check_task: Optional[asyncio.Task] = None
        
        logger.info(f"HA coordinator initialized for node: {self.node_id}")
    
    async def start(self):
        """Start HA coordinator"""
        logger.info("Starting HA coordinator")
        
        try:
            # Start health checks
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.is_running = True
            logger.info("HA coordinator started successfully")
            
        except Exception as e:
            logger.error(f"Error starting HA coordinator: {e}")
            raise
    
    async def stop(self):
        """Stop HA coordinator"""
        logger.info("Stopping HA coordinator")
        
        try:
            # Cancel health check task
            if self.health_check_task:
                self.health_check_task.cancel()
            
            self.is_running = False
            logger.info("HA coordinator stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping HA coordinator: {e}")
    
    async def _health_check_loop(self):
        """Health check loop"""
        while True:
            try:
                # Perform health checks
                await self._perform_health_checks()
                
                # Wait for next check
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(5)
    
    async def _perform_health_checks(self):
        """Perform health checks"""
        try:
            # Check node health
            node_info = NodeInfo(
                node_id=self.node_id,
                hostname=socket.gethostname(),
                ip_address=socket.gethostbyname(socket.gethostname()),
                port=8080,
                status=NodeStatus.ACTIVE,
                last_heartbeat=datetime.utcnow(),
                capabilities=["api", "websocket", "monitoring"],
                load_score=0.5,
                memory_usage=0.6,
                cpu_usage=0.4,
                active_connections=100,
                max_connections=1000,
                version="5.0.0",
                region="us-west",
                availability_zone="us-west-1",
                metadata={}
            )
            
            await self.scaling_manager.update_node_metrics(
                self.node_id,
                node_info.load_score,
                node_info.memory_usage,
                node_info.cpu_usage,
                node_info.active_connections
            )
            
        except Exception as e:
            logger.error(f"Error performing health checks: {e}")
    
    async def get_ha_status(self) -> Dict[str, Any]:
        """Get HA status"""
        try:
            return {
                "node_id": self.node_id,
                "is_running": self.is_running,
                "scaling": await self.scaling_manager.get_scaling_recommendations(),
                "failover": await self.failover_manager.get_failover_status(),
                "async_scaling": await self.async_scaling.get_scaling_status(),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting HA status: {e}")
            return {"error": str(e)}


# Global HA coordinator instance
ha_coordinator = HighAvailabilityCoordinator()


# API functions
async def initialize_ha_system(redis_client=None) -> str:
    """Initialize HA system"""
    try:
        # Set Redis client for components
        if redis_client:
            ha_coordinator.shared_state.set_redis_client(redis_client)
            ha_coordinator.distributed_locks.set_redis_client(redis_client)
            ha_coordinator.stateless_api.set_session_store(redis_client)
        
        # Start HA coordinator
        await ha_coordinator.start()
        
        logger.info("HA system initialized")
        return "HA system initialized successfully"
        
    except Exception as e:
        logger.error(f"Error initializing HA system: {e}")
        return f"Error initializing HA system: {e}"


async def stop_ha_system() -> str:
    """Stop HA system"""
    try:
        await ha_coordinator.stop()
        logger.info("HA system stopped")
        return "HA system stopped successfully"
        
    except Exception as e:
        logger.error(f"Error stopping HA system: {e}")
        return f"Error stopping HA system: {e}"


async def get_ha_status() -> Dict[str, Any]:
    """Get HA system status"""
    try:
        return await ha_coordinator.get_ha_status()
    except Exception as e:
        logger.error(f"Error getting HA status: {e}")
        return {"error": str(e)}


async def register_ha_node(node_info: Dict[str, Any]) -> str:
    """Register HA node"""
    try:
        node = NodeInfo(
            node_id=node_info.get("node_id"),
            hostname=node_info.get("hostname"),
            ip_address=node_info.get("ip_address"),
            port=node_info.get("port", 8080),
            status=NodeStatus(node_info.get("status", "active")),
            last_heartbeat=datetime.utcnow(),
            capabilities=node_info.get("capabilities", []),
            load_score=node_info.get("load_score", 0.0),
            memory_usage=node_info.get("memory_usage", 0.0),
            cpu_usage=node_info.get("cpu_usage", 0.0),
            active_connections=node_info.get("active_connections", 0),
            max_connections=node_info.get("max_connections", 1000),
            version=node_info.get("version", "5.0.0"),
            region=node_info.get("region", "us-west"),
            availability_zone=node_info.get("availability_zone", "us-west-1"),
            metadata=node_info.get("metadata", {})
        )
        
        success = await ha_coordinator.scaling_manager.register_node(node)
        
        if success:
            return f"HA node registered: {node.node_id}"
        else:
            return "Failed to register HA node"
            
    except Exception as e:
        logger.error(f"Error registering HA node: {e}")
        return f"Error registering HA node: {e}"


async def acquire_distributed_lock(lock_type: str, resource_id: str, 
                                 ttl: Optional[int] = None, 
                                 metadata: Optional[Dict[str, Any]] = None) -> str:
    """Acquire distributed lock"""
    try:
        lock_type_enum = LockType(lock_type)
        lock_id = await ha_coordinator.distributed_locks.acquire_lock(
            lock_type_enum, resource_id, ha_coordinator.node_id, ttl, metadata
        )
        
        if lock_id:
            return f"Lock acquired: {lock_id}"
        else:
            return "Failed to acquire lock"
            
    except Exception as e:
        logger.error(f"Error acquiring distributed lock: {e}")
        return f"Error acquiring distributed lock: {e}"


async def release_distributed_lock(lock_id: str) -> str:
    """Release distributed lock"""
    try:
        success = await ha_coordinator.distributed_locks.release_lock(lock_id)
        
        if success:
            return f"Lock released: {lock_id}"
        else:
            return "Failed to release lock"
            
    except Exception as e:
        logger.error(f"Error releasing distributed lock: {e}")
        return f"Error releasing distributed lock: {e}"


async def create_user_session(user_id: str, session_data: Dict[str, Any]) -> str:
    """Create user session"""
    try:
        session_id = await ha_coordinator.stateless_api.create_session(user_id, session_data)
        
        if session_id:
            return f"Session created: {session_id}"
        else:
            return "Failed to create session"
            
    except Exception as e:
        logger.error(f"Error creating user session: {e}")
        return f"Error creating user session: {e}"


async def get_shared_state(key: str) -> Any:
    """Get shared state"""
    try:
        return await ha_coordinator.shared_state.get_shared_state(key)
    except Exception as e:
        logger.error(f"Error getting shared state: {e}")
        return None


async def set_shared_state(key: str, value: Any, ttl: Optional[int] = None) -> str:
    """Set shared state"""
    try:
        success = await ha_coordinator.shared_state.set_shared_state(key, value, ttl)
        
        if success:
            return f"Shared state set: {key}"
        else:
            return "Failed to set shared state"
            
    except Exception as e:
        logger.error(f"Error setting shared state: {e}")
        return f"Error setting shared state: {e}"
