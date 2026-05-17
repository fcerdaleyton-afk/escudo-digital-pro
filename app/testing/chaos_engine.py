#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Defensive Chaos Testing Suite
Comprehensive chaos testing for resilience validation under stress
"""

import os
import sys
import asyncio
import logging
import json
import time
import random
import uuid
import signal
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref
import traceback

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/chaos_testing.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ChaosTestType(Enum):
    """Chaos test type enumeration"""
    WORKER_FAILURE = "worker_failure"
    WEBSOCKET_INTERRUPTION = "websocket_interruption"
    REDIS_OUTAGE = "redis_outage"
    MALFORMED_REQUESTS = "malformed_requests"
    ASYNC_TIMEOUT = "async_timeout"
    QUEUE_SATURATION = "queue_saturation"
    NETWORK_PARTITION = "network_partition"
    MEMORY_PRESSURE = "memory_pressure"
    CPU_PRESSURE = "cpu_pressure"
    DISK_PRESSURE = "disk_pressure"


class ChaosSeverity(Enum):
    """Chaos test severity enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TestStatus(Enum):
    """Test status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class ChaosTestConfig:
    """Chaos test configuration"""
    test_type: ChaosTestType
    severity: ChaosSeverity
    duration: int  # seconds
    intensity: float  # 0.0 to 1.0
    target_components: List[str]
    cooldown_period: int  # seconds
    auto_recovery: bool = True
    max_concurrent_failures: int = 5
    safety_checks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChaosTestEvent:
    """Chaos test event data"""
    event_id: str
    test_type: ChaosTestType
    severity: ChaosSeverity
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime]
    duration: int
    target_components: List[str]
    intensity: float
    results: Dict[str, Any]
    metrics: Dict[str, Any]
    errors: List[str]
    recovery_time: Optional[timedelta]
    success: bool
    metadata: Dict[str, Any]


@dataclass
class ChaosTestMetrics:
    """Chaos test metrics"""
    test_id: str
    test_type: ChaosTestType
    start_time: datetime
    end_time: Optional[datetime]
    duration: timedelta
    success: bool
    recovery_time: Optional[timedelta]
    system_impact: Dict[str, float]
    component_impact: Dict[str, float]
    performance_impact: Dict[str, float]
    error_count: int
    recovery_count: int
    resilience_score: float


class WorkerFailureSimulator:
    """Worker failure simulator"""
    
    def __init__(self):
        """Initialize worker failure simulator"""
        self.active_workers: Dict[str, Dict[str, Any]] = {}
        self.failure_history: List[Dict[str, Any]] = []
        self.recovery_history: List[Dict[str, Any]] = []
        self.failure_rate: float = 0.1
        self.recovery_time: int = 30  # seconds
        self.max_failures: int = 5
        
        logger.info("Worker failure simulator initialized")
    
    async def simulate_worker_failure(self, worker_id: str, failure_type: str = "crash") -> bool:
        """Simulate worker failure"""
        try:
            if worker_id not in self.active_workers:
                return False
            
            worker_info = self.active_workers[worker_id]
            
            # Record failure
            failure_event = {
                'worker_id': worker_id,
                'failure_type': failure_type,
                'timestamp': datetime.utcnow(),
                'reason': f"Simulated {failure_type} failure",
                'state_before': worker_info.get('state', 'unknown'),
                'pid': worker_info.get('pid'),
                'memory_usage': worker_info.get('memory_usage', 0.0),
                'cpu_usage': worker_info.get('cpu_usage', 0.0)
            }
            
            self.failure_history.append(failure_event)
            
            # Simulate failure
            if failure_type == "crash":
                # Simulate process crash
                pid = worker_info.get('pid')
                if pid:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        logger.warning(f"Process {pid} not found for worker {worker_id}")
            
            elif failure_type == "hang":
                # Simulate process hang
                worker_info['state'] = 'hung'
                worker_info['hung_at'] = datetime.utcnow()
            
            elif failure_type == "memory_leak":
                # Simulate memory leak
                worker_info['memory_usage'] = min(95.0, worker_info.get('memory_usage', 0.0) + 20.0)
                worker_info['state'] = 'memory_pressure'
            
            elif failure_type == "cpu_spike":
                # Simulate CPU spike
                worker_info['cpu_usage'] = min(95.0, worker_info.get('cpu_usage', 0.0) + 30.0)
                worker_info['state'] = 'cpu_pressure'
            
            logger.info(f"Worker failure simulated: {worker_id} - {failure_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating worker failure: {e}")
            return False
    
    async def simulate_worker_recovery(self, worker_id: str) -> bool:
        """Simulate worker recovery"""
        try:
            if worker_id not in self.active_workers:
                return False
            
            worker_info = self.active_workers[worker_id]
            
            # Record recovery
            recovery_event = {
                'worker_id': worker_id,
                'timestamp': datetime.utcnow(),
                'reason': "Simulated worker recovery",
                'state_before': worker_info.get('state', 'unknown'),
                'failure_duration': (datetime.utcnow() - worker_info.get('failed_at', datetime.utcnow())).total_seconds()
            }
            
            self.recovery_history.append(recovery_event)
            
            # Simulate recovery
            worker_info['state'] = 'active'
            worker_info['memory_usage'] = max(0.0, worker_info.get('memory_usage', 0.0) - 10.0)
            worker_info['cpu_usage'] = max(0.0, worker_info.get('cpu_usage', 0.0) - 10.0)
            
            logger.info(f"Worker recovery simulated: {worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating worker recovery: {e}")
            return False
    
    async def get_failure_metrics(self) -> Dict[str, Any]:
        """Get failure metrics"""
        try:
            total_failures = len(self.failure_history)
            total_recoveries = len(self.recovery_history)
            active_failures = len([w for w in self.active_workers.values() if w.get('state') != 'active'])
            
            # Calculate failure rate
            if total_failures > 0:
                recovery_rate = total_recoveries / total_failures
            else:
                recovery_rate = 1.0
            
            return {
                'total_failures': total_failures,
                'total_recoveries': total_recoveries,
                'active_failures': active_failures,
                'recovery_rate': recovery_rate,
                'failure_history': self.failure_history[-10:],  # Last 10 failures
                'recovery_history': self.recovery_history[-10:]  # Last 10 recoveries
            }
            
        except Exception as e:
            logger.error(f"Error getting failure metrics: {e}")
            return {'error': str(e)}


class WebSocketInterruptionSimulator:
    """WebSocket interruption simulator"""
    
    def __init__(self):
        """Initialize WebSocket interruption simulator"""
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        self.interruption_history: List[Dict[str, Any]] = []
        self.recovery_history: List[Dict[str, Any]] = []
        self.interruption_types = [
            "connection_drop",
            "message_loss",
            "latency_spike",
            "bandwidth_limit",
            "protocol_error"
        ]
        
        logger.info("WebSocket interruption simulator initialized")
    
    async def simulate_connection_drop(self, connection_id: str) -> bool:
        """Simulate WebSocket connection drop"""
        try:
            if connection_id not in self.active_connections:
                return False
            
            connection_info = self.active_connections[connection_id]
            
            # Record interruption
            interruption_event = {
                'connection_id': connection_id,
                'interruption_type': 'connection_drop',
                'timestamp': datetime.utcnow(),
                'reason': 'Simulated connection drop',
                'messages_before': connection_info.get('message_count', 0),
                'client_ip': connection_info.get('client_ip'),
                'connected_at': connection_info.get('connected_at')
            }
            
            self.interruption_history.append(interruption_event)
            
            # Simulate connection drop
            connection_info['state'] = 'disconnected'
            connection_info['disconnected_at'] = datetime.utcnow()
            
            logger.info(f"WebSocket connection drop simulated: {connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating connection drop: {e}")
            return False
    
    async def simulate_message_loss(self, connection_id: str, loss_rate: float = 0.5) -> bool:
        """Simulate message loss"""
        try:
            if connection_id not in self.active_connections:
                return False
            
            connection_info = self.active_connections[connection_id]
            
            # Record interruption
            interruption_event = {
                'connection_id': connection_id,
                'interruption_type': 'message_loss',
                'timestamp': datetime.utcnow(),
                'reason': f'Simulated message loss: {loss_rate * 100}%',
                'loss_rate': loss_rate,
                'client_ip': connection_info.get('client_ip')
            }
            
            self.interruption_history.append(interruption_event)
            
            # Simulate message loss
            connection_info['message_loss_rate'] = loss_rate
            connection_info['state'] = 'degraded'
            
            logger.info(f"WebSocket message loss simulated: {connection_id} - {loss_rate * 100}%")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating message loss: {e}")
            return False
    
    async def simulate_latency_spike(self, connection_id: str, latency_ms: int = 1000) -> bool:
        """Simulate WebSocket latency spike"""
        try:
            if connection_id not in self.active_connections:
                return False
            
            connection_info = self.active_connections[connection_id]
            
            # Record interruption
            interruption_event = {
                'connection_id': connection_id,
                'interruption_type': 'latency_spike',
                'timestamp': datetime.utcnow(),
                'reason': f'Simulated latency spike: {latency_ms}ms',
                'latency_ms': latency_ms,
                'client_ip': connection_info.get('client_ip')
            }
            
            self.interruption_history.append(interruption_event)
            
            # Simulate latency spike
            connection_info['latency_ms'] = latency_ms
            connection_info['state'] = 'degraded'
            
            logger.info(f"WebSocket latency spike simulated: {connection_id} - {latency_ms}ms")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating latency spike: {e}")
            return False
    
    async def simulate_websocket_recovery(self, connection_id: str) -> bool:
        """Simulate WebSocket recovery"""
        try:
            if connection_id not in self.active_connections:
                return False
            
            connection_info = self.active_connections[connection_id]
            
            # Record recovery
            recovery_event = {
                'connection_id': connection_id,
                'timestamp': datetime.utcnow(),
                'reason': 'Simulated WebSocket recovery',
                'state_before': connection_info.get('state', 'unknown'),
                'interruption_duration': (datetime.utcnow() - connection_info.get('interruption_at', datetime.utcnow())).total_seconds()
            }
            
            self.recovery_history.append(recovery_event)
            
            # Simulate recovery
            connection_info['state'] = 'active'
            connection_info['latency_ms'] = 0
            connection_info['message_loss_rate'] = 0.0
            connection_info['recovered_at'] = datetime.utcnow()
            
            logger.info(f"WebSocket recovery simulated: {connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating WebSocket recovery: {e}")
            return False
    
    async def get_interruption_metrics(self) -> Dict[str, Any]:
        """Get interruption metrics"""
        try:
            total_interruptions = len(self.interruption_history)
            total_recoveries = len(self.recovery_history)
            active_interruptions = len([c for c in self.active_connections.values() if c.get('state') != 'active'])
            
            # Calculate recovery rate
            if total_interruptions > 0:
                recovery_rate = total_recoveries / total_interruptions
            else:
                recovery_rate = 1.0
            
            return {
                'total_interruptions': total_interruptions,
                'total_recoveries': total_recoveries,
                'active_interruptions': active_interruptions,
                'recovery_rate': recovery_rate,
                'interruption_history': self.interruption_history[-10:],
                'recovery_history': self.recovery_history[-10:]
            }
            
        except Exception as e:
            logger.error(f"Error getting interruption metrics: {e}")
            return {'error': str(e)}


class RedisOutageSimulator:
    """Redis outage simulator"""
    
    def __init__(self):
        """Initialize Redis outage simulator"""
        self.redis_client = None
        self.outage_history: List[Dict[str, Any]] = []
        self.recovery_history: List[Dict[str, Any]] = []
        self.outage_types = [
            "connection_loss",
            "memory_exhaustion",
            "cpu_spike",
            "disk_full",
            "network_partition"
        ]
        self.is_outage_active: bool = False
        
        logger.info("Redis outage simulator initialized")
    
    def set_redis_client(self, redis_client):
        """Set Redis client for simulation"""
        self.redis_client = redis_client
    
    async def simulate_connection_loss(self, duration: int = 30) -> bool:
        """Simulate Redis connection loss"""
        try:
            if self.is_outage_active:
                return False
            
            # Record outage
            outage_event = {
                'outage_type': 'connection_loss',
                'timestamp': datetime.utcnow(),
                'duration': duration,
                'reason': 'Simulated Redis connection loss',
                'affected_operations': []
            }
            
            self.outage_history.append(outage_event)
            self.is_outage_active = True
            
            # Simulate connection loss
            # In a real implementation, this would block Redis operations
            logger.warning(f"Redis connection loss simulated for {duration} seconds")
            
            # Schedule recovery
            asyncio.create_task(self._schedule_recovery(duration, 'connection_loss'))
            
            return True
            
        except Exception as e:
            logger.error(f"Error simulating Redis connection loss: {e}")
            return False
    
    async def simulate_memory_exhaustion(self, duration: int = 30) -> bool:
        """Simulate Redis memory exhaustion"""
        try:
            if self.is_outage_active:
                return False
            
            # Record outage
            outage_event = {
                'outage_type': 'memory_exhaustion',
                'timestamp': datetime.utcnow(),
                'duration': duration,
                'reason': 'Simulated Redis memory exhaustion',
                'affected_operations': ['set', 'get', 'incr', 'expire']
            }
            
            self.outage_history.append(outage_event)
            self.is_outage_active = True
            
            # Simulate memory exhaustion
            logger.warning(f"Redis memory exhaustion simulated for {duration} seconds")
            
            # Schedule recovery
            asyncio.create_task(self._schedule_recovery(duration, 'memory_exhaustion'))
            
            return True
            
        except Exception as e:
            logger.error(f"Error simulating Redis memory exhaustion: {e}")
            return False
    
    async def simulate_cpu_spike(self, duration: int = 30) -> bool:
        """Simulate Redis CPU spike"""
        try:
            if self.is_outage_active:
                return False
            
            # Record outage
            outage_event = {
                'outage_type': 'cpu_spike',
                'timestamp': datetime.utcnow(),
                'duration': duration,
                'reason': 'Simulated Redis CPU spike',
                'affected_operations': ['slow_operations']
            }
            
            self.outage_history.append(outage_event)
            self.is_outage_active = True
            
            # Simulate CPU spike
            logger.warning(f"Redis CPU spike simulated for {duration} seconds")
            
            # Schedule recovery
            asyncio.create_task(self._schedule_recovery(duration, 'cpu_spike'))
            
            return True
            
        except Exception as e:
            logger.error(f"Error simulating Redis CPU spike: {e}")
            return False
    
    async def _schedule_recovery(self, duration: int, outage_type: str):
        """Schedule recovery from outage"""
        try:
            await asyncio.sleep(duration)
            
            # Record recovery
            recovery_event = {
                'outage_type': outage_type,
                'timestamp': datetime.utcnow(),
                'reason': f'Simulated Redis recovery from {outage_type}',
                'outage_duration': duration
            }
            
            self.recovery_history.append(recovery_event)
            self.is_outage_active = False
            
            logger.info(f"Redis recovery simulated from {outage_type}")
            
        except Exception as e:
            logger.error(f"Error scheduling Redis recovery: {e}")
    
    async def get_outage_metrics(self) -> Dict[str, Any]:
        """Get outage metrics"""
        try:
            total_outages = len(self.outage_history)
            total_recoveries = len(self.recovery_history)
            
            # Calculate recovery rate
            if total_outages > 0:
                recovery_rate = total_recoveries / total_outages
            else:
                recovery_rate = 1.0
            
            return {
                'total_outages': total_outages,
                'total_recoveries': total_recoveries,
                'is_outage_active': self.is_outage_active,
                'recovery_rate': recovery_rate,
                'outage_history': self.outage_history[-10:],
                'recovery_history': self.recovery_history[-10:]
            }
            
        except Exception as e:
            logger.error(f"Error getting outage metrics: {e}")
            return {'error': str(e)}


class MalformedRequestSimulator:
    """Malformed request flood simulator"""
    
    def __init__(self):
        """Initialize malformed request simulator"""
        self.request_history: List[Dict[str, Any]] = []
        self.malformed_patterns = [
            "invalid_json",
            "oversized_payload",
            "missing_headers",
            "invalid_method",
            "invalid_endpoint",
            "encoding_error",
            "unicode_error",
            "null_bytes"
        ]
        self.flood_intensity: int = 100  # requests per second
        self.flood_duration: int = 60  # seconds
        
        logger.info("Malformed request simulator initialized")
    
    def generate_malformed_request(self) -> Dict[str, Any]:
        """Generate a malformed request"""
        try:
            pattern = random.choice(self.malformed_patterns)
            
            if pattern == "invalid_json":
                return self._generate_invalid_json_request()
            elif pattern == "oversized_payload":
                return self._generate_oversized_request()
            elif pattern == "missing_headers":
                return self._generate_missing_headers_request()
            elif pattern == "invalid_method":
                return self._generate_invalid_method_request()
            elif pattern == "invalid_endpoint":
                return self._generate_invalid_endpoint_request()
            elif pattern == "encoding_error":
                return self._generate_encoding_error_request()
            elif pattern == "unicode_error":
                return self._generate_unicode_error_request()
            elif pattern == "null_bytes":
                return self._generate_null_bytes_request()
            else:
                return self._generate_invalid_json_request()
                
        except Exception as e:
            logger.error(f"Error generating malformed request: {e}")
            return {}
    
    def _generate_invalid_json_request(self) -> Dict[str, Any]:
        """Generate invalid JSON request"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"invalid": json, "missing": "bracket"}',
            'malformed_type': 'invalid_json'
        }
    
    def _generate_oversized_request(self) -> Dict[str, Any]:
        """Generate oversized request"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"data": "' + 'x' * 1000000 + '"}',  # 1MB payload
            'malformed_type': 'oversized_payload'
        }
    
    def _generate_missing_headers_request(self) -> Dict[str, Any]:
        """Generate request with missing headers"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {},
            'body': '{"data": "test"}',
            'malformed_type': 'missing_headers'
        }
    
    def _generate_invalid_method_request(self) -> Dict[str, Any]:
        """Generate request with invalid method"""
        return {
            'method': 'INVALID',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"data": "test"}',
            'malformed_type': 'invalid_method'
        }
    
    def _generate_invalid_endpoint_request(self) -> Dict[str, Any]:
        """Generate request with invalid endpoint"""
        return {
            'method': 'POST',
            'endpoint': '/invalid/endpoint/that/does/not/exist',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"data": "test"}',
            'malformed_type': 'invalid_endpoint'
        }
    
    def _generate_encoding_error_request(self) -> Dict[str, Any]:
        """Generate request with encoding error"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': b'\x80\x81\x82\x83invalid_bytes',
            'malformed_type': 'encoding_error'
        }
    
    def _generate_unicode_error_request(self) -> Dict[str, Any]:
        """Generate request with unicode error"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"data": "\ud800\ud801\ud802invalid_unicode"}',
            'malformed_type': 'unicode_error'
        }
    
    def _generate_null_bytes_request(self) -> Dict[str, Any]:
        """Generate request with null bytes"""
        return {
            'method': 'POST',
            'endpoint': '/api/test',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': None,
            'malformed_type': 'null_bytes'
        }
    
    async def simulate_request_flood(self, intensity: int = 100, duration: int = 60) -> bool:
        """Simulate malformed request flood"""
        try:
            logger.info(f"Starting malformed request flood: {intensity} req/s for {duration}s")
            
            start_time = time.time()
            end_time = start_time + duration
            request_count = 0
            
            while time.time() < end_time:
                # Generate malformed request
                request = self.generate_malformed_request()
                
                # Record request
                request_event = {
                    'timestamp': datetime.utcnow(),
                    'malformed_type': request.get('malformed_type'),
                    'method': request.get('method'),
                    'endpoint': request.get('endpoint'),
                    'request_id': f"malformed_{request_count}"
                }
                
                self.request_history.append(request_event)
                request_count += 1
                
                # Rate limiting
                await asyncio.sleep(1.0 / intensity)
            
            logger.info(f"Malformed request flood completed: {request_count} requests")
            return True
            
        except Exception as e:
            logger.error(f"Error simulating request flood: {e}")
            return False
    
    async def get_flood_metrics(self) -> Dict[str, Any]:
        """Get flood metrics"""
        try:
            total_requests = len(self.request_history)
            
            # Count by malformed type
            malformed_counts = {}
            for request in self.request_history:
                malformed_type = request.get('malformed_type', 'unknown')
                if malformed_type not in malformed_counts:
                    malformed_counts[malformed_type] = 0
                malformed_counts[malformed_type] += 1
            
            return {
                'total_requests': total_requests,
                'malformed_counts': malformed_counts,
                'request_history': self.request_history[-20:]
            }
            
        except Exception as e:
            logger.error(f"Error getting flood metrics: {e}")
            return {'error': str(e)}


class AsyncTimeoutSimulator:
    """Async timeout simulator"""
    
    def __init__(self):
        """Initialize async timeout simulator"""
        self.timeout_history: List[Dict[str, Any]] = []
        self.recovery_history: List[Dict[str, Any]] = []
        self.timeout_types = [
            "database_timeout",
            "redis_timeout",
            "api_timeout",
            "websocket_timeout",
            "file_io_timeout",
            "network_timeout"
        ]
        
        logger.info("Async timeout simulator initialized")
    
    async def simulate_timeout(self, operation_type: str, timeout_duration: int = 30) -> bool:
        """Simulate async timeout"""
        try:
            # Record timeout
            timeout_event = {
                'operation_type': operation_type,
                'timestamp': datetime.utcnow(),
                'timeout_duration': timeout_duration,
                'reason': f'Simulated {operation_type} timeout',
                'operation_id': str(uuid.uuid4())
            }
            
            self.timeout_history.append(timeout_event)
            
            # Simulate timeout
            logger.warning(f"Simulated {operation_type} timeout: {timeout_duration}s")
            
            # Schedule recovery
            asyncio.create_task(self._simulate_timeout_recovery(timeout_event['operation_id'], operation_type))
            
            return True
            
        except Exception as e:
            logger.error(f"Error simulating timeout: {e}")
            return False
    
    async def _simulate_timeout_recovery(self, operation_id: str, operation_type: str):
        """Simulate timeout recovery"""
        try:
            await asyncio.sleep(5)  # Recovery time
            
            # Record recovery
            recovery_event = {
                'operation_id': operation_id,
                'operation_type': operation_type,
                'timestamp': datetime.utcnow(),
                'reason': f'Simulated {operation_type} recovery',
                'recovery_time': 5
            }
            
            self.recovery_history.append(recovery_event)
            
            logger.info(f"Simulated {operation_type} recovery")
            
        except Exception as e:
            logger.error(f"Error simulating timeout recovery: {e}")
    
    async def get_timeout_metrics(self) -> Dict[str, Any]:
        """Get timeout metrics"""
        try:
            total_timeouts = len(self.timeout_history)
            total_recoveries = len(self.recovery_history)
            
            # Calculate recovery rate
            if total_timeouts > 0:
                recovery_rate = total_recoveries / total_timeouts
            else:
                recovery_rate = 1.0
            
            # Count by operation type
            timeout_counts = {}
            for timeout in self.timeout_history:
                op_type = timeout.get('operation_type', 'unknown')
                if op_type not in timeout_counts:
                    timeout_counts[op_type] = 0
                timeout_counts[op_type] += 1
            
            return {
                'total_timeouts': total_timeouts,
                'total_recoveries': total_recoveries,
                'recovery_rate': recovery_rate,
                'timeout_counts': timeout_counts,
                'timeout_history': self.timeout_history[-10:],
                'recovery_history': self.recovery_history[-10:]
            }
            
        except Exception as e:
            logger.error(f"Error getting timeout metrics: {e}")
            return {'error': str(e)}


class QueueSaturationSimulator:
    """Queue saturation simulator"""
    
    def __init__(self):
        """Initialize queue saturation simulator"""
        self.queues: Dict[str, Dict[str, Any]] = {}
        self.saturation_history: List[Dict[str, Any]] = []
        self.recovery_history: List[Dict[str, Any]] = []
        self.max_queue_size = 10000
        self.saturation_threshold = 0.8
        
        logger.info("Queue saturation simulator initialized")
    
    def register_queue(self, queue_id: str, max_size: int = 10000):
        """Register a queue for simulation"""
        self.queues[queue_id] = {
            'queue_id': queue_id,
            'max_size': max_size,
            'current_size': 0,
            'processing_rate': 0.0,
            'failed_operations': 0,
            'last_activity': datetime.utcnow()
        }
    
    async def simulate_queue_saturation(self, queue_id: str, saturation_level: float = 0.9) -> bool:
        """Simulate queue saturation"""
        try:
            if queue_id not in self.queues:
                return False
            
            queue = self.queues[queue_id]
            
            # Record saturation
            saturation_event = {
                'queue_id': queue_id,
                'timestamp': datetime.utcnow(),
                'saturation_level': saturation_level,
                'reason': f'Simulated queue saturation: {saturation_level * 100}%',
                'size_before': queue['current_size'],
                'max_size': queue['max_size']
            }
            
            self.saturation_history.append(saturation_event)
            
            # Simulate saturation
            target_size = int(queue['max_size'] * saturation_level)
            queue['current_size'] = target_size
            queue['processing_rate'] = 0.0  # Processing stops when saturated
            queue['failed_operations'] += 1
            queue['last_activity'] = datetime.utcnow()
            
            logger.warning(f"Queue saturation simulated: {queue_id} at {saturation_level * 100}%")
            
            # Schedule recovery
            asyncio.create_task(self._simulate_queue_recovery(queue_id))
            
            return True
            
        except Exception as e:
            logger.error(f"Error simulating queue saturation: {e}")
            return False
    
    async def _simulate_queue_recovery(self, queue_id: str):
        """Simulate queue recovery"""
        try:
            await asyncio.sleep(10)  # Recovery time
            
            if queue_id not in self.queues:
                return
            
            queue = self.queues[queue_id]
            
            # Record recovery
            recovery_event = {
                'queue_id': queue_id,
                'timestamp': datetime.utcnow(),
                'reason': 'Simulated queue recovery',
                'size_before': queue['current_size'],
                'size_after': 0,
                'recovery_time': 10
            }
            
            self.recovery_history.append(recovery_event)
            
            # Simulate recovery
            queue['current_size'] = 0
            queue['processing_rate'] = 100.0  # Processing resumes
            queue['failed_operations'] = 0
            queue['last_activity'] = datetime.utcnow()
            
            logger.info(f"Queue recovery simulated: {queue_id}")
            
        except Exception as e:
            logger.error(f"Error simulating queue recovery: {e}")
    
    async def get_saturation_metrics(self) -> Dict[str, Any]:
        """Get saturation metrics"""
        try:
            total_saturations = len(self.saturation_history)
            total_recoveries = len(self.recovery_history)
            
            # Calculate recovery rate
            if total_saturations > 0:
                recovery_rate = total_recoveries / total_saturations
            else:
                recovery_rate = 1.0
            
            # Queue status
            queue_status = {}
            for queue_id, queue in self.queues.items():
                saturation_level = queue['current_size'] / queue['max_size']
                queue_status[queue_id] = {
                    'current_size': queue['current_size'],
                    'max_size': queue['max_size'],
                    'saturation_level': saturation_level,
                    'processing_rate': queue['processing_rate'],
                    'failed_operations': queue['failed_operations'],
                    'is_saturated': saturation_level > self.saturation_threshold
                }
            
            return {
                'total_saturations': total_saturations,
                'total_recoveries': total_recoveries,
                'recovery_rate': recovery_rate,
                'queue_status': queue_status,
                'saturation_history': self.saturation_history[-10:],
                'recovery_history': self.recovery_history[-10:]
            }
            
        except Exception as e:
            logger.error(f"Error getting saturation metrics: {e}")
            return {'error': str(e)}


class ChaosTestingEngine:
    """Main chaos testing engine coordinator"""
    
    def __init__(self):
        """Initialize chaos testing engine"""
        self.worker_simulator = WorkerFailureSimulator()
        self.websocket_simulator = WebSocketInterruptionSimulator()
        self.redis_simulator = RedisOutageSimulator()
        self.request_simulator = MalformedRequestSimulator()
        self.timeout_simulator = AsyncTimeoutSimulator()
        self.queue_simulator = QueueSaturationSimulator()
        
        self.test_events: List[ChaosTestEvent] = []
        self.test_metrics: List[ChaosTestMetrics] = []
        self.is_running = False
        self.safety_checks_enabled: bool = True
        self.max_concurrent_tests: int = 3
        self.active_tests: Dict[str, asyncio.Task] = {}
        
        # Initialize default queues
        self.queue_simulator.register_queue('task_queue')
        self.queue_simulator.register_queue('message_queue')
        self.queue_simulator.register_queue('event_queue')
        
        logger.info("Chaos testing engine initialized")
    
    async def start(self):
        """Start chaos testing engine"""
        logger.info("Starting chaos testing engine")
        
        self.is_running = True
        
        # Start background monitoring
        asyncio.create_task(self._monitoring_loop())
        
        logger.info("Chaos testing engine started")
    
    async def stop(self):
        """Stop chaos testing engine"""
        logger.info("Stopping chaos testing engine")
        
        self.is_running = False
        
        # Cancel all active tests
        for test_id, task in self.active_tests.items():
            task.cancel()
        
        logger.info("Chaos testing engine stopped")
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.is_running:
            try:
                # Check safety conditions
                if self.safety_checks_enabled:
                    await self._check_safety_conditions()
                
                # Update metrics
                await self._update_metrics()
                
                # Wait for next iteration
                await asyncio.sleep(10)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)
    
    async def _check_safety_conditions(self):
        """Check safety conditions"""
        try:
            # Check system load
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
            
            # Check if system is under stress
            if cpu_usage > 90 or memory_usage > 90:
                logger.warning("System under stress, pausing chaos tests")
                
                # Cancel all active tests
                for test_id, task in self.active_tests.items():
                    task.cancel()
                    self.active_tests[test_id] = None
                
                # Wait for system to recover
                await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Error checking safety conditions: {e}")
    
    async def _update_metrics(self):
        """Update chaos testing metrics"""
        try:
            # Get metrics from all simulators
            worker_metrics = await self.worker_simulator.get_failure_metrics()
            websocket_metrics = await self.websocket_simulator.get_interruption_metrics()
            redis_metrics = await self.redis_simulator.get_outage_metrics()
            request_metrics = await self.request_simulator.get_flood_metrics()
            timeout_metrics = await self.timeout_simulator.get_timeout_metrics()
            queue_metrics = await self.queue_simulator.get_saturation_metrics()
            
            # Update overall metrics
            self.test_metrics.append(ChaosTestMetrics(
                test_id="system_overall",
                test_type=ChaosTestType.WORKER_FAILURE,
                start_time=datetime.utcnow(),
                end_time=None,
                duration=timedelta(),
                success=True,
                recovery_time=None,
                system_impact={
                    'worker_failures': worker_metrics.get('total_failures', 0),
                    'websocket_interruptions': websocket_metrics.get('total_interruptions', 0),
                    'redis_outages': redis_metrics.get('total_outages', 0),
                    'request_errors': request_metrics.get('total_requests', 0),
                    'timeouts': timeout_metrics.get('total_timeouts', 0),
                    'queue_saturations': queue_metrics.get('total_saturations', 0)
                },
                component_impact={},
                performance_impact={},
                error_count=0,
                recovery_count=0,
                resilience_score=self._calculate_resilience_score()
            ))
            
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
    
    def _calculate_resilience_score(self) -> float:
        """Calculate overall resilience score"""
        try:
            # Get recent metrics
            if len(self.test_metrics) < 10:
                return 1.0
            
            recent_metrics = self.test_metrics[-10:]
            
            # Calculate component-specific scores
            scores = []
            for metric in recent_metrics:
                component_score = 1.0
                
                # Penalize failures
                component_score -= metric.system_impact.get('worker_failures', 0) * 0.1
                component_score -= metric.system_impact.get('websocket_interruptions', 0) * 0.1
                component_score -= metric.system_impact.get('redis_outages', 0) * 0.15
                component_score -= metric.system_impact.get('request_errors', 0) * 0.05
                component_score -= metric.system_impact.get('timeouts', 0) * 0.05
                component_score -= metric.system_impact.get('queue_saturations', 0) * 0.1
                
                # Reward recoveries
                component_score += metric.recovery_count * 0.05
                
                # Ensure score is between 0 and 1
                scores.append(max(0.0, min(1.0, component_score)))
            
            # Calculate overall score
            if scores:
                return sum(scores) / len(scores)
            else:
                return 1.0
                
        except Exception as e:
            logger.error(f"Error calculating resilience score: {e}")
            return 0.0
    
    async def run_chaos_test(self, test_type: ChaosTestType, config: ChaosTestConfig) -> str:
        """Run a chaos test"""
        try:
            if len(self.active_tests) >= self.max_concurrent_tests:
                return "Maximum concurrent tests reached"
            
            test_id = str(uuid.uuid4())
            
            # Create test event
            test_event = ChaosTestEvent(
                event_id=test_id,
                test_type=test_type,
                severity=config.severity,
                status=TestStatus.PENDING,
                start_time=datetime.utcnow(),
                end_time=None,
                duration=config.duration,
                target_components=config.target_components,
                intensity=config.intensity,
                results={},
                metrics={},
                errors=[],
                recovery_time=None,
                success=False,
                metadata=config.metadata
            )
            
            self.test_events.append(test_event)
            
            # Start test
            task = asyncio.create_task(self._execute_chaos_test(test_event, config))
            self.active_tests[test_id] = task
            
            return f"Chaos test started: {test_id} ({test_type.value})"
            
        except Exception as e:
            logger.error(f"Error running chaos test: {e}")
            return f"Error running chaos test: {e}"
    
    async def _execute_chaos_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute a chaos test"""
        try:
            test_event.status = TestStatus.RUNNING
            test_event.start_time = datetime.utcnow()
            
            logger.info(f"Executing chaos test: {test_event.event_id} ({test_event.test_type.value})")
            
            # Execute based on test type
            if test_event.test_type == ChaosTestType.WORKER_FAILURE:
                await self._execute_worker_failure_test(test_event, config)
            elif test_event.test_type == ChaosTestType.WEBSOCKET_INTERRUPTION:
                await self._execute_websocket_interruption_test(test_event, config)
            elif test_event.test_type == ChaosTestType.REDIS_OUTAGE:
                await self._execute_redis_outage_test(test_event, config)
            elif test_event.test_type == ChaosTestType.MALFORMED_REQUESTS:
                await self._execute_malformed_requests_test(test_event, config)
            elif test_event.test_type == ChaosTestType.ASYNC_TIMEOUT:
                await self._execute_async_timeout_test(test_event, config)
            elif test_event.test_type == ChaosTestType.QUEUE_SATURATION:
                await self._execute_queue_saturation_test(test_event, config)
            
            # Mark as completed
            test_event.status = TestStatus.COMPLETED
            test_event.end_time = datetime.utcnow()
            test_event.duration = test_event.end_time - test_event.start_time
            test_event.success = True
            
            logger.info(f"Chaos test completed: {test_event.event_id}")
            
        except Exception as e:
            logger.error(f"Error executing chaos test {test_event.event_id}: {e}")
            test_event.status = TestStatus.FAILED
            test_event.end_time = datetime.utcnow()
            test_event.errors.append(str(e))
    
    async def _execute_worker_failure_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute worker failure test"""
        try:
            # Register test workers
            worker_ids = []
            for i in range(config.intensity * 5):
                worker_id = f"test_worker_{i}"
                self.worker_simulator.active_workers[worker_id] = {
                    'state': 'active',
                    'pid': 1000 + i,
                    'memory_usage': 50.0,
                    'cpu_usage': 30.0
                }
                worker_ids.append(worker_id)
            
            # Simulate failures
            failed_workers = []
            for worker_id in worker_ids[:int(config.intensity * 3)]:
                failure_type = random.choice(['crash', 'hang', 'memory_leak', 'cpu_spike'])
                success = await self.worker_simulator.simulate_worker_failure(worker_id, failure_type)
                if success:
                    failed_workers.append(worker_id)
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Simulate recoveries
            recovered_workers = []
            for worker_id in failed_workers:
                success = await self.worker_simulator.simulate_worker_recovery(worker_id)
                if success:
                    recovered_workers.append(worker_id)
            
            # Update test results
            test_event.results = {
                'failed_workers': failed_workers,
                'recovered_workers': recovered_workers,
                'total_workers': len(worker_ids),
                'failure_rate': len(failed_workers) / len(worker_ids) if worker_ids else 0,
                'recovery_rate': len(recovered_workers) / len(failed_workers) if failed_workers else 1.0
            }
            
            test_event.metrics = await self.worker_simulator.get_failure_metrics()
            
        except Exception as e:
            logger.error(f"Error executing worker failure test: {e}")
            test_event.errors.append(str(e))
    
    async def _execute_websocket_interruption_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute WebSocket interruption test"""
        try:
            # Register test connections
            connection_ids = []
            for i in range(int(config.intensity * 10)):
                connection_id = f"test_ws_{i}"
                self.websocket_simulator.active_connections[connection_id] = {
                    'state': 'active',
                    'client_ip': f"192.168.1.{100 + i}",
                    'message_count': 0,
                    'connected_at': datetime.utcnow()
                }
                connection_ids.append(connection_id)
            
            # Simulate interruptions
            interrupted_connections = []
            for connection_id in connection_ids[:int(config.intensity * 5)]:
                interruption_type = random.choice(['connection_drop', 'message_loss', 'latency_spike'])
                
                if interruption_type == 'connection_drop':
                    success = await self.websocket_simulator.simulate_connection_drop(connection_id)
                elif interruption_type == 'message_loss':
                    success = await self.websocket_simulator.simulate_message_loss(connection_id, config.intensity)
                elif interruption_type == 'latency_spike':
                    success = await self.websocket_simulator.simulate_latency_spike(connection_id, int(config.intensity * 1000))
                
                if success:
                    interrupted_connections.append(connection_id)
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Simulate recoveries
            recovered_connections = []
            for connection_id in interrupted_connections:
                success = await self.websocket_simulator.simulate_websocket_recovery(connection_id)
                if success:
                    recovered_connections.append(connection_id)
            
            # Update test results
            test_event.results = {
                'interrupted_connections': interrupted_connections,
                'recovered_connections': recovered_connections,
                'total_connections': len(connection_ids),
                'interruption_rate': len(interrupted_connections) / len(connection_ids) if connection_ids else 0,
                'recovery_rate': len(recovered_connections) / len(interrupted_connections) if interrupted_connections else 1.0
            }
            
            test_event.metrics = await self.websocket_simulator.get_interruption_metrics()
            
        except Exception as e:
            logger.error(f"Error executing WebSocket interruption test: {e}")
            test_event.errors.append(str(e))
    
    async def _execute_redis_outage_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute Redis outage test"""
        try:
            # Simulate Redis outage
            outage_type = random.choice(['connection_loss', 'memory_exhaustion', 'cpu_spike'])
            
            if outage_type == 'connection_loss':
                success = await self.redis_simulator.simulate_connection_loss(config.duration)
            elif outage_type == 'memory_exhaustion':
                success = await self.redis_simulator.simulate_memory_exhaustion(config.duration)
            elif outage_type == 'cpu_spike':
                success = await self.redis_simulator.simulate_cpu_spike(config.duration)
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Update test results
            test_event.results = {
                'outage_type': outage_type,
                'outage_duration': config.duration,
                'success': success
            }
            
            test_event.metrics = await self.redis_simulator.get_outage_metrics()
            
        except Exception as e:
            logger.error(f"Error executing Redis outage test: {e}")
            test_event.errors.append(str(e))
    
    async def _execute_malformed_requests_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute malformed requests test"""
        try:
            # Simulate request flood
            intensity = int(config.intensity * 100)
            success = await self.request_simulator.simulate_request_flood(intensity, config.duration)
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Update test results
            test_event.results = {
                'intensity': intensity,
                'duration': config.duration,
                'success': success
            }
            
            test_event.metrics = await self.request_simulator.get_flood_metrics()
            
        except Exception as e:
            logger.error(f"Error executing malformed requests test: {e}")
            test_event.errors.append(str(e))
    
    async def _execute_async_timeout_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute async timeout test"""
        try:
            # Simulate timeouts
            timeout_duration = int(config.intensity * 30)
            
            for i in range(int(config.intensity * 3)):
                operation_type = random.choice(['database_timeout', 'redis_timeout', 'api_timeout', 'websocket_timeout'])
                success = await self.timeout_simulator.simulate_timeout(operation_type, timeout_duration)
                
                if i < int(config.intensity * 3) - 1:
                    await asyncio.sleep(5)  # Wait between timeouts
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Update test results
            test_event.results = {
                'timeout_count': int(config.intensity * 3),
                'timeout_duration': timeout_duration,
                'success': True
            }
            
            test_event.metrics = await self.timeout_simulator.get_timeout_metrics()
            
        except Exception as e:
            logger.error(f"Error executing async timeout test: {e}")
            test_event.errors.append(str(e))
    
    async def _execute_queue_saturation_test(self, test_event: ChaosTestEvent, config: ChaosTestConfig):
        """Execute queue saturation test"""
        try:
            # Simulate queue saturation
            saturation_level = min(config.intensity, 1.0)
            
            for queue_id in ['task_queue', 'message_queue', 'event_queue']:
                success = await self.queue_simulator.simulate_queue_saturation(queue_id, saturation_level)
                
                if queue_id < 'event_queue':  # Wait between queue saturations
                    await asyncio.sleep(5)
            
            # Wait for test duration
            await asyncio.sleep(config.duration)
            
            # Update test results
            test_event.results = {
                'saturation_level': saturation_level,
                'duration': config.duration,
                'success': True
            }
            
            test_event.metrics = await self.queue_simulator.get_saturation_metrics()
            
        except Exception as e:
            logger.error(f"Error executing queue saturation test: {e}")
            test_event.errors.append(str(e))
    
    async def get_test_results(self, test_id: Optional[str] = None) -> Dict[str, Any]:
        """Get chaos test results"""
        try:
            if test_id:
                # Get specific test
                for event in self.test_events:
                    if event.event_id == test_id:
                        return {
                            'event_id': event.event_id,
                            'test_type': event.test_type.value,
                            'severity': event.severity.value,
                            'status': event.status.value,
                            'start_time': event.start_time.isoformat(),
                            'end_time': event.end_time.isoformat() if event.end_time else None,
                            'duration': event.duration.total_seconds(),
                            'target_components': event.target_components,
                            'intensity': event.intensity,
                            'results': event.results,
                            'metrics': event.metrics,
                            'errors': event.errors,
                            'success': event.success,
                            'metadata': event.metadata
                        }
            else:
                # Get all tests
                return {
                    'total_tests': len(self.test_events),
                    'active_tests': len([t for t in self.test_events if t.status == TestStatus.RUNNING]),
                    'completed_tests': len([t for t in self.test_events if t.status == TestStatus.COMPLETED]),
                    'failed_tests': len([t for t in self.test_events if t.status == TestStatus.FAILED]),
                    'test_events': [
                        {
                            'event_id': event.event_id,
                            'test_type': event.test_type.value,
                            'severity': event.severity.value,
                            'status': event.status.value,
                            'start_time': event.start_time.isoformat(),
                            'end_time': event.end_time.isoformat() if event.end_time else None,
                            'duration': event.duration.total_seconds(),
                            'success': event.success
                        }
                        for event in self.test_events
                    ],
                    'resilience_score': self._calculate_resilience_score()
                }
            
        except Exception as e:
            logger.error(f"Error getting test results: {e}")
            return {'error': str(e)}
    
    async def get_chaos_dashboard(self) -> Dict[str, Any]:
        """Get chaos testing dashboard"""
        try:
            # Get all metrics
            worker_metrics = await self.worker_simulator.get_failure_metrics()
            websocket_metrics = await self.websocket_simulator.get_interruption_metrics()
            redis_metrics = await self.redis_simulator.get_outage_metrics()
            request_metrics = await self.request_simulator.get_flood_metrics()
            timeout_metrics = await self.timeout_simulator.get_timeout_metrics()
            queue_metrics = await self.queue_simulator.get_saturation_metrics()
            
            # Calculate overall statistics
            total_tests = len(self.test_events)
            active_tests = len([t for t in self.test_events if t.status == TestStatus.RUNNING])
            completed_tests = len([t for t in self.test_events if t.status == TestStatus.COMPLETED])
            failed_tests = len([t for t in self.test_events if t.status == TestStatus.FAILED])
            
            success_rate = completed_tests / total_tests if total_tests > 0 else 1.0
            
            return {
                'is_running': self.is_running,
                'safety_checks_enabled': self.safety_checks_enabled,
                'max_concurrent_tests': self.max_concurrent_tests,
                'statistics': {
                    'total_tests': total_tests,
                    'active_tests': active_tests,
                    'completed_tests': completed_tests,
                    'failed_tests': failed_tests,
                    'success_rate': success_rate,
                    'resilience_score': self._calculate_resilience_score()
                },
                'simulators': {
                    'worker_failure': worker_metrics,
                    'websocket_interruption': websocket_metrics,
                    'redis_outage': redis_metrics,
                    'malformed_requests': request_metrics,
                    'async_timeout': timeout_metrics,
                    'queue_saturation': queue_metrics
                },
                'recent_tests': [
                    {
                        'event_id': event.event_id,
                        'test_type': event.test_type.value,
                        'severity': event.severity.value,
                        'status': event.status.value,
                        'success': event.success,
                        'duration': event.duration.total_seconds(),
                        'timestamp': event.start_time.isoformat()
                    }
                    for event in self.test_events[-10:]
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting chaos dashboard: {e}")
            return {'error': str(e)}


# Global chaos testing engine instance
chaos_testing_engine = ChaosTestingEngine()


# API functions
async def initialize_chaos_testing() -> str:
    """Initialize chaos testing engine"""
    try:
        await chaos_testing_engine.start()
        logger.info("Chaos testing engine initialized")
        return "Chaos testing engine initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing chaos testing engine: {e}")
        return f"Error initializing chaos testing engine: {e}"


async def stop_chaos_testing() -> str:
    """Stop chaos testing engine"""
    try:
        await chaos_testing_engine.stop()
        logger.info("Chaos testing engine stopped")
        return "Chaos testing engine stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping chaos testing engine: {e}")
        return f"Error stopping chaos testing engine: {e}"


async def run_chaos_test(test_type: str, severity: str = 'medium', duration: int = 60, 
                           intensity: float = 0.5, target_components: List[str] = None) -> str:
    """Run a chaos test"""
    try:
        # Parse parameters
        test_type_enum = ChaosTestType(test_type)
        severity_enum = ChaosSeverity(severity)
        
        # Create config
        config = ChaosTestConfig(
            test_type=test_type_enum,
            severity=severity_enum,
            duration=duration,
            intensity=intensity,
            target_components=target_components or [],
            cooldown_period=300,
            auto_recovery=True,
            max_concurrent_failures=5,
            safety_checks=['system_load', 'memory_usage', 'cpu_usage']
        )
        
        # Run test
        result = await chaos_testing_engine.run_chaos_test(test_type_enum, config)
        
        return result
        
    except Exception as e:
        logger.error(f"Error running chaos test: {e}")
        return f"Error running chaos test: {e}"


async def get_chaos_dashboard() -> Dict[str, Any]:
    """Get chaos testing dashboard"""
    try:
        return await chaos_testing_engine.get_chaos_dashboard()
    except Exception as e:
        logger.error(f"Error getting chaos dashboard: {e}")
        return {'error': str(e)}


async def get_test_results(test_id: Optional[str] = None) -> Dict[str, Any]:
    """Get chaos test results"""
    try:
        return await chaos_testing_engine.get_test_results(test_id)
    except Exception as e:
        logger.error(f"Error getting test results: {e}")
        return {'error': str(e)}


# Initialize chaos testing engine
async def initialize_chaos_testing_suite() -> str:
    """Initialize chaos testing suite"""
    try:
        await initialize_chaos_testing()
        logger.info("Chaos testing suite initialized")
        return "Chaos testing suite initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing chaos testing suite: {e}")
        return f"Error initializing chaos testing suite: {e}"


# Cleanup function
async def cleanup_chaos_testing() -> str:
    """Cleanup chaos testing suite"""
    try:
        await stop_chaos_testing()
        logger.info("Chaos testing suite cleaned up")
        return "Chaos testing suite cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up chaos testing suite: {e}")
        return f"Error cleaning up chaos testing suite: {e}"
