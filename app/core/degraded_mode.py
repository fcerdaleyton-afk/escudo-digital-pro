#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Degraded Mode Fallback System
Automatic degraded mode activation with service adaptation and resilience
"""

import os
import sys
import asyncio
import logging
import json
import time
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
        logging.FileHandler('/app/logs/degraded_mode.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DegradationLevel(Enum):
    """Degradation level enumeration"""
    NONE = 0.0          # Full functionality
    MINIMAL = 0.2       # Minimal functionality
    BASIC = 0.4         # Basic functionality
    STANDARD = 0.6      # Standard functionality
    ENHANCED = 0.8      # Enhanced functionality
    FULL = 1.0          # Full functionality


class ServiceStatus(Enum):
    """Service status enumeration"""
    ACTIVE = "active"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    MAINTENANCE = "maintenance"


class TriggerType(Enum):
    """Degradation trigger type"""
    HEALTH_SCORE = "health_score"
    RESOURCE_USAGE = "resource_usage"
    ERROR_RATE = "error_rate"
    RESPONSE_TIME = "response_time"
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    EXTERNAL = "external"


@dataclass
class ServiceConfig:
    """Service configuration for degraded mode"""
    service_name: str
    priority: int  # 1-10, 1 being highest priority
    min_degradation_level: DegradationLevel
    max_degradation_level: DegradationLevel
    resource_requirements: Dict[str, float]
    dependencies: List[str]
    fallback_handlers: Dict[str, Callable]
    health_check_interval: int = 30
    auto_degrade: bool = True
    manual_override: bool = False


@dataclass
class DegradationEvent:
    """Degradation event data"""
    event_id: str
    trigger_type: TriggerType
    service_name: str
    from_level: DegradationLevel
    to_level: DegradationLevel
    timestamp: datetime
    reason: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    duration: Optional[timedelta] = None
    resolved: bool = False
    resolution_time: Optional[datetime] = None


@dataclass
class SystemMetrics:
    """System-wide metrics"""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: float
    active_connections: int
    request_rate: float
    error_rate: float
    response_time: float
    health_score: float
    timestamp: datetime


class DegradedModeManager:
    """Degraded mode manager with automatic fallback"""
    
    def __init__(self):
        """Initialize degraded mode manager"""
        self.current_level = DegradationLevel.FULL
        self.services: Dict[str, ServiceConfig] = {}
        self.service_status: Dict[str, ServiceStatus] = {}
        self.degradation_events: List[DegradationEvent] = []
        self.system_metrics: Optional[SystemMetrics] = None
        self.monitoring_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # Configuration
        self.config = {
            'health_check_interval': 30,
            'degradation_threshold': 0.7,
            'recovery_threshold': 0.8,
            'max_degradation_level': DegradationLevel.MINIMAL,
            'auto_recovery': True,
            'grace_period': 300,  # 5 minutes
            'metrics_retention': 86400,  # 24 hours
        }
        
        # Statistics
        self.stats = {
            'total_degradations': 0,
            'auto_degradations': 0,
            'manual_degradations': 0,
            'recoveries': 0,
            'average_degradation_time': 0.0,
            'current_degraded_services': 0
        }
        
        # Initialize default services
        self._initialize_default_services()
        
        logger.info("Degraded mode manager initialized")
    
    def _initialize_default_services(self):
        """Initialize default service configurations"""
        services = [
            ServiceConfig(
                service_name="api_gateway",
                priority=1,
                min_degradation_level=DegradationLevel.BASIC,
                max_degradation_level=DegradationLevel.MINIMAL,
                resource_requirements={"cpu": 0.1, "memory": 100, "connections": 100},
                dependencies=[],
                fallback_handlers={
                    "rate_limiting": self._fallback_rate_limiting,
                    "circuit_breaker": self._fallback_circuit_breaker,
                    "cache_fallback": self._fallback_cache_fallback
                }
            ),
            ServiceConfig(
                service_name="database",
                priority=1,
                min_degradation_level=DegradationLevel.STANDARD,
                max_degradation_level=DegradationLevel.BASIC,
                resource_requirements={"cpu": 0.2, "memory": 512, "connections": 50},
                dependencies=[],
                fallback_handlers={
                    "read_replica": self._fallback_read_replica,
                    "connection_pooling": self._fallback_connection_pooling,
                    "query_caching": self._fallback_query_caching
                }
            ),
            ServiceConfig(
                service_name="redis",
                priority=2,
                min_degradation_level=DegradationLevel.BASIC,
                max_degradation_level=DegradationLevel.MINIMAL,
                resource_requirements={"cpu": 0.1, "memory": 256, "connections": 100},
                dependencies=[],
                fallback_handlers={
                    "local_cache": self._fallback_local_cache,
                    "reduced_ttl": self._fallback_reduced_ttl,
                    "compression": self._fallback_compression
                }
            ),
            ServiceConfig(
                service_name="websocket",
                priority=3,
                min_degradation_level=DegradationLevel.STANDARD,
                max_degradation_level=DegradationLevel.MINIMAL,
                resource_requirements={"cpu": 0.15, "memory": 128, "connections": 1000},
                dependencies=[],
                fallback_handlers={
                    "connection_limiting": self._fallback_connection_limiting,
                    "message_throttling": self._fallback_message_throttling,
                    "fallback_polling": self._fallback_polling
                }
            ),
            ServiceConfig(
                service_name="security_scanner",
                priority=4,
                min_degradation_level=DegradationLevel.ENHANCED,
                max_degradation_level=DegradationLevel.BASIC,
                resource_requirements={"cpu": 0.3, "memory": 1024, "connections": 10},
                dependencies=["database", "redis"],
                fallback_handlers={
                    "reduced_scanning": self._fallback_reduced_scanning,
                    "cached_results": self._fallback_cached_results,
                    "priority_scanning": self._fallback_priority_scanning
                }
            ),
            ServiceConfig(
                service_name="threat_analyzer",
                priority=4,
                min_degradation_level=DegradationLevel.ENHANCED,
                max_degradation_level=DegradationLevel.BASIC,
                resource_requirements={"cpu": 0.4, "memory": 2048, "connections": 5},
                dependencies=["database", "redis", "security_scanner"],
                fallback_handlers={
                    "simplified_analysis": self._fallback_simplified_analysis,
                    "batch_processing": self._fallback_batch_processing,
                    "rule_based": self._fallback_rule_based
                }
            ),
            ServiceConfig(
                service_name="monitoring",
                priority=5,
                min_degradation_level=DegradationLevel.STANDARD,
                max_degradation_level=DegradationLevel.MINIMAL,
                resource_requirements={"cpu": 0.05, "memory": 64, "connections": 10},
                dependencies=[],
                fallback_handlers={
                    "reduced_metrics": self._fallback_reduced_metrics,
                    "sampling": self._fallback_sampling,
                    "batch_reporting": self._fallback_batch_reporting
                }
            )
        ]
        
        for service in services:
            self.services[service.service_name] = service
            self.service_status[service.service_name] = ServiceStatus.ACTIVE
    
    async def start(self):
        """Start the degraded mode manager"""
        logger.info("Starting degraded mode manager")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Degraded mode manager started")
    
    async def stop(self):
        """Stop the degraded mode manager"""
        logger.info("Stopping degraded mode manager")
        
        # Cancel monitoring task
        if self.monitoring_task:
            self.monitoring_task.cancel()
        
        # Restore full functionality
        await self.set_degradation_level(DegradationLevel.FULL, TriggerType.MANUAL, "System shutdown")
        
        logger.info("Degraded mode manager stopped")
    
    async def set_degradation_level(self, level: DegradationLevel, trigger_type: TriggerType, reason: str) -> bool:
        """Set system degradation level"""
        try:
            with self._lock:
                from_level = self.current_level
                self.current_level = level
            
            # Create degradation event
            event = DegradationEvent(
                event_id=f"degradation_{int(time.time())}",
                trigger_type=trigger_type,
                service_name="system",
                from_level=from_level,
                to_level=level,
                timestamp=datetime.utcnow(),
                reason=reason
            )
            
            # Apply degradation
            await self._apply_degradation(event)
            
            # Update statistics
            if trigger_type in [TriggerType.HEALTH_SCORE, TriggerType.RESOURCE_USAGE, TriggerType.ERROR_RATE, TriggerType.RESPONSE_TIME]:
                self.stats['auto_degradations'] += 1
            else:
                self.stats['manual_degradations'] += 1
            
            self.stats['total_degradations'] += 1
            
            logger.info(f"Degradation level set to {level.value} from {from_level.value} - {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting degradation level: {e}")
            return False
    
    async def _apply_degradation(self, event: DegradationEvent):
        """Apply degradation to services"""
        try:
            logger.info(f"Applying degradation: {event.from_level.value} -> {event.to_level.value}")
            
            # Determine which services to degrade
            services_to_degrade = self._get_services_to_degrade(event.to_level)
            
            # Apply service-specific degradation
            for service_name in services_to_degrade:
                await self._degrade_service(service_name, event.to_level)
            
            # Store event
            self.degradation_events.append(event)
            
            # Clean old events
            await self._cleanup_old_events()
            
        except Exception as e:
            logger.error(f"Error applying degradation: {e}")
    
    def _get_services_to_degrade(self, level: DegradationLevel) -> List[str]:
        """Get services that should be degraded at given level"""
        try:
            services_to_degrade = []
            
            for service_name, service_config in self.services.items():
                # Check if service should be degraded at this level
                if level.value < service_config.min_degradation_level.value:
                    services_to_degrade.append(service_name)
                elif level.value < service_config.max_degradation_level.value:
                    services_to_degrade.append(service_name)
            
            # Sort by priority
            services_to_degrade.sort(key=lambda x: self.services[x].priority)
            
            return services_to_degrade
            
        except Exception as e:
            logger.error(f"Error getting services to degrade: {e}")
            return []
    
    async def _degrade_service(self, service_name: str, level: DegradationLevel):
        """Degrade a specific service"""
        try:
            service_config = self.services.get(service_name)
            if not service_config:
                return
            
            logger.info(f"Degrading service {service_name} to level {level.value}")
            
            # Update service status
            if level.value < 0.5:
                self.service_status[service_name] = ServiceStatus.DEGRADED
            elif level.value < 0.2:
                self.service_status[service_name] = ServiceStatus.DISABLED
            else:
                self.service_status[service_name] = ServiceStatus.ACTIVE
            
            # Apply fallback handlers
            await self._apply_fallback_handlers(service_name, level)
            
            # Update statistics
            if self.service_status[service_name] in [ServiceStatus.DEGRADED, ServiceStatus.DISABLED]:
                self.stats['current_degraded_services'] += 1
            
        except Exception as e:
            logger.error(f"Error degrading service {service_name}: {e}")
    
    async def _apply_fallback_handlers(self, service_name: str, level: DegradationLevel):
        """Apply fallback handlers for a service"""
        try:
            service_config = self.services.get(service_name)
            if not service_config:
                return
            
            # Apply handlers based on degradation level
            if level.value <= 0.2:  # MINIMAL
                handlers = ["cache_fallback", "connection_limiting", "reduced_metrics"]
            elif level.value <= 0.4:  # BASIC
                handlers = ["rate_limiting", "local_cache", "reduced_scanning"]
            elif level.value <= 0.6:  # STANDARD
                handlers = ["circuit_breaker", "connection_pooling"]
            elif level.value <= 0.8:  # ENHANCED
                handlers = ["read_replica", "query_caching"]
            else:
                handlers = []
            
            for handler_name in handlers:
                handler = service_config.fallback_handlers.get(handler_name)
                if handler:
                    try:
                        await handler(service_name, level)
                    except Exception as e:
                        logger.error(f"Error applying fallback handler {handler_name} for {service_name}: {e}")
            
        except Exception as e:
            logger.error(f"Error applying fallback handlers for {service_name}: {e}")
    
    # Fallback handler implementations
    async def _fallback_rate_limiting(self, service_name: str, level: DegradationLevel):
        """Apply rate limiting fallback"""
        try:
            # Reduce rate limits based on degradation level
            reduction_factor = max(0.1, level.value)
            logger.info(f"Applying rate limiting to {service_name} with reduction factor {reduction_factor}")
            
            # Implementation would adjust rate limits
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying rate limiting fallback: {e}")
    
    async def _fallback_circuit_breaker(self, service_name: str, level: DegradationLevel):
        """Apply circuit breaker fallback"""
        try:
            # Enable circuit breaker with adjusted thresholds
            logger.info(f"Applying circuit breaker to {service_name}")
            
            # Implementation would enable circuit breaker
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying circuit breaker fallback: {e}")
    
    async def _fallback_cache_fallback(self, service_name: str, level: DegradationLevel):
        """Apply cache fallback"""
        try:
            # Enable cache fallback with extended TTL
            logger.info(f"Applying cache fallback to {service_name}")
            
            # Implementation would enable cache fallback
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying cache fallback: {e}")
    
    async def _fallback_read_replica(self, service_name: str, level: DegradationLevel):
        """Apply read replica fallback"""
        try:
            # Route read queries to replica
            logger.info(f"Applying read replica fallback to {service_name}")
            
            # Implementation would route to replica
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying read replica fallback: {e}")
    
    async def _fallback_connection_pooling(self, service_name: str, level: DegradationLevel):
        """Apply connection pooling fallback"""
        try:
            # Reduce connection pool size
            reduction_factor = max(0.3, level.value)
            logger.info(f"Applying connection pooling to {service_name} with reduction factor {reduction_factor}")
            
            # Implementation would reduce pool size
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying connection pooling fallback: {e}")
    
    async def _fallback_query_caching(self, service_name: str, level: DegradationLevel):
        """Apply query caching fallback"""
        try:
            # Enable aggressive query caching
            logger.info(f"Applying query caching to {service_name}")
            
            # Implementation would enable caching
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying query caching fallback: {e}")
    
    async def _fallback_local_cache(self, service_name: str, level: DegradationLevel):
        """Apply local cache fallback"""
        try:
            # Enable local in-memory cache
            logger.info(f"Applying local cache to {service_name}")
            
            # Implementation would enable local cache
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying local cache fallback: {e}")
    
    async def _fallback_reduced_ttl(self, service_name: str, level: DegradationLevel):
        """Apply reduced TTL fallback"""
        try:
            # Reduce cache TTL
            ttl_factor = max(0.5, level.value)
            logger.info(f"Applying reduced TTL to {service_name} with factor {ttl_factor}")
            
            # Implementation would reduce TTL
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying reduced TTL fallback: {e}")
    
    async def _fallback_compression(self, service_name: str, level: DegradationLevel):
        """Apply compression fallback"""
        try:
            # Enable data compression
            logger.info(f"Applying compression to {service_name}")
            
            # Implementation would enable compression
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying compression fallback: {e}")
    
    async def _fallback_connection_limiting(self, service_name: str, level: DegradationLevel):
        """Apply connection limiting fallback"""
        try:
            # Limit concurrent connections
            limit_factor = max(0.1, level.value)
            logger.info(f"Applying connection limiting to {service_name} with factor {limit_factor}")
            
            # Implementation would limit connections
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying connection limiting fallback: {e}")
    
    async def _fallback_message_throttling(self, service_name: str, level: DegradationLevel):
        """Apply message throttling fallback"""
        try:
            # Throttle message processing
            throttle_factor = max(0.2, level.value)
            logger.info(f"Applying message throttling to {service_name} with factor {throttle_factor}")
            
            # Implementation would throttle messages
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying message throttling fallback: {e}")
    
    async def _fallback_polling(self, service_name: str, level: DegradationLevel):
        """Apply polling fallback"""
        try:
            # Switch to polling mode
            logger.info(f"Applying polling fallback to {service_name}")
            
            # Implementation would switch to polling
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying polling fallback: {e}")
    
    async def _fallback_reduced_scanning(self, service_name: str, level: DegradationLevel):
        """Apply reduced scanning fallback"""
        try:
            # Reduce scanning frequency
            scan_factor = max(0.3, level.value)
            logger.info(f"Applying reduced scanning to {service_name} with factor {scan_factor}")
            
            # Implementation would reduce scanning
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying reduced scanning fallback: {e}")
    
    async def _fallback_cached_results(self, service_name: str, level: DegradationLevel):
        """Apply cached results fallback"""
        try:
            # Use cached results when possible
            logger.info(f"Applying cached results to {service_name}")
            
            # Implementation would use cached results
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying cached results fallback: {e}")
    
    async def _fallback_priority_scanning(self, service_name: str, level: DegradationLevel):
        """Apply priority scanning fallback"""
        try:
            # Only scan high-priority items
            logger.info(f"Applying priority scanning to {service_name}")
            
            # Implementation would prioritize scanning
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying priority scanning fallback: {e}")
    
    async def _fallback_simplified_analysis(self, service_name: str, level: DegradationLevel):
        """Apply simplified analysis fallback"""
        try:
            # Use simplified analysis algorithms
            logger.info(f"Applying simplified analysis to {service_name}")
            
            # Implementation would simplify analysis
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying simplified analysis fallback: {e}")
    
    async def _fallback_batch_processing(self, service_name: str, level: DegradationLevel):
        """Apply batch processing fallback"""
        try:
            # Process items in batches
            logger.info(f"Applying batch processing to {service_name}")
            
            # Implementation would enable batch processing
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying batch processing fallback: {e}")
    
    async def _fallback_rule_based(self, service_name: str, level: DegradationLevel):
        """Apply rule-based fallback"""
        try:
            # Use rule-based analysis instead of ML
            logger.info(f"Applying rule-based analysis to {service_name}")
            
            # Implementation would use rules
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying rule-based fallback: {e}")
    
    async def _fallback_reduced_metrics(self, service_name: str, level: DegradationLevel):
        """Apply reduced metrics fallback"""
        try:
            # Reduce metrics collection
            reduction_factor = max(0.3, level.value)
            logger.info(f"Applying reduced metrics to {service_name} with factor {reduction_factor}")
            
            # Implementation would reduce metrics
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying reduced metrics fallback: {e}")
    
    async def _fallback_sampling(self, service_name: str, level: DegradationLevel):
        """Apply sampling fallback"""
        try:
            # Sample metrics instead of collecting all
            sample_rate = max(0.1, level.value)
            logger.info(f"Applying sampling to {service_name} with rate {sample_rate}")
            
            # Implementation would sample metrics
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying sampling fallback: {e}")
    
    async def _fallback_batch_reporting(self, service_name: str, level: DegradationLevel):
        """Apply batch reporting fallback"""
        try:
            # Report metrics in batches
            logger.info(f"Applying batch reporting to {service_name}")
            
            # Implementation would batch reports
            # For now, we'll just log the action
            
        except Exception as e:
            logger.error(f"Error applying batch reporting fallback: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Update system metrics
                await self._update_system_metrics()
                
                # Check for degradation triggers
                await self._check_degradation_triggers()
                
                # Check for recovery opportunities
                await self._check_recovery_opportunities()
                
                # Update statistics
                await self._update_statistics()
                
                # Wait for next iteration
                await asyncio.sleep(self.config['health_check_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)  # Brief delay before retry
    
    async def _update_system_metrics(self):
        """Update system-wide metrics"""
        try:
            import psutil
            
            # Get system metrics
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get network metrics
            network = psutil.net_io_counters()
            
            # Get application metrics (simulated)
            active_connections = 100
            request_rate = 1000.0
            error_rate = 0.01
            response_time = 0.1
            
            # Calculate health score
            health_score = self._calculate_health_score(
                cpu_usage, memory.percent, disk.percent, error_rate, response_time
            )
            
            # Update metrics
            self.system_metrics = SystemMetrics(
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_io=network.bytes_sent + network.bytes_recv,
                active_connections=active_connections,
                request_rate=request_rate,
                error_rate=error_rate,
                response_time=response_time,
                health_score=health_score,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")
    
    def _calculate_health_score(self, cpu_usage: float, memory_usage: float, 
                              disk_usage: float, error_rate: float, response_time: float) -> float:
        """Calculate system health score"""
        try:
            score = 1.0
            
            # Penalize high resource usage
            if cpu_usage > 80:
                score -= (cpu_usage - 80) * 0.01
            
            if memory_usage > 80:
                score -= (memory_usage - 80) * 0.01
            
            if disk_usage > 90:
                score -= (disk_usage - 90) * 0.01
            
            # Penalize high error rate
            if error_rate > 0.05:
                score -= (error_rate - 0.05) * 2.0
            
            # Penalize high response time
            if response_time > 1.0:
                score -= (response_time - 1.0) * 0.1
            
            # Ensure score is between 0 and 1
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
            return 0.0
    
    async def _check_degradation_triggers(self):
        """Check for degradation triggers"""
        try:
            if not self.system_metrics:
                return
            
            # Check health score trigger
            if self.system_metrics.health_score < self.config['degradation_threshold']:
                target_level = self._calculate_target_degradation_level(self.system_metrics.health_score)
                await self.set_degradation_level(
                    target_level, 
                    TriggerType.HEALTH_SCORE, 
                    f"Health score {self.system_metrics.health_score:.2f} below threshold {self.config['degradation_threshold']}"
                )
                return
            
            # Check resource usage triggers
            if (self.system_metrics.cpu_usage > 90 or 
                self.system_metrics.memory_usage > 90 or 
                self.system_metrics.disk_usage > 95):
                await self.set_degradation_level(
                    DegradationLevel.BASIC,
                    TriggerType.RESOURCE_USAGE,
                    f"High resource usage: CPU {self.system_metrics.cpu_usage}%, Memory {self.system_metrics.memory_usage}%, Disk {self.system_metrics.disk_usage}%"
                )
                return
            
            # Check error rate trigger
            if self.system_metrics.error_rate > 0.1:
                await self.set_degradation_level(
                    DegradationLevel.STANDARD,
                    TriggerType.ERROR_RATE,
                    f"High error rate: {self.system_metrics.error_rate:.2%}"
                )
                return
            
            # Check response time trigger
            if self.system_metrics.response_time > 2.0:
                await self.set_degradation_level(
                    DegradationLevel.ENHANCED,
                    TriggerType.RESPONSE_TIME,
                    f"High response time: {self.system_metrics.response_time:.2f}s"
                )
                return
                
        except Exception as e:
            logger.error(f"Error checking degradation triggers: {e}")
    
    def _calculate_target_degradation_level(self, health_score: float) -> DegradationLevel:
        """Calculate target degradation level based on health score"""
        try:
            if health_score < 0.2:
                return DegradationLevel.MINIMAL
            elif health_score < 0.4:
                return DegradationLevel.BASIC
            elif health_score < 0.6:
                return DegradationLevel.STANDARD
            elif health_score < 0.8:
                return DegradationLevel.ENHANCED
            else:
                return DegradationLevel.FULL
                
        except Exception as e:
            logger.error(f"Error calculating target degradation level: {e}")
            return DegradationLevel.BASIC
    
    async def _check_recovery_opportunities(self):
        """Check for recovery opportunities"""
        try:
            if not self.config['auto_recovery'] or not self.system_metrics:
                return
            
            # Check if system health has improved
            if self.system_metrics.health_score > self.config['recovery_threshold']:
                # Calculate target recovery level
                target_level = self._calculate_target_recovery_level(self.system_metrics.health_score)
                
                if target_level.value > self.current_level.value:
                    await self.set_degradation_level(
                        target_level,
                        TriggerType.HEALTH_SCORE,
                        f"System health improved to {self.system_metrics.health_score:.2f}"
                    )
                    
                    # Update statistics
                    self.stats['recoveries'] += 1
                    
        except Exception as e:
            logger.error(f"Error checking recovery opportunities: {e}")
    
    def _calculate_target_recovery_level(self, health_score: float) -> DegradationLevel:
        """Calculate target recovery level based on health score"""
        try:
            if health_score > 0.9:
                return DegradationLevel.FULL
            elif health_score > 0.8:
                return DegradationLevel.ENHANCED
            elif health_score > 0.6:
                return DegradationLevel.STANDARD
            elif health_score > 0.4:
                return DegradationLevel.BASIC
            else:
                return DegradationLevel.MINIMAL
                
        except Exception as e:
            logger.error(f"Error calculating target recovery level: {e}")
            return DegradationLevel.BASIC
    
    async def _update_statistics(self):
        """Update degradation statistics"""
        try:
            # Update current degraded services count
            self.stats['current_degraded_services'] = len([
                service for service, status in self.service_status.items()
                if status in [ServiceStatus.DEGRADED, ServiceStatus.DISABLED]
            ])
            
            # Calculate average degradation time
            if self.degradation_events:
                total_degradation_time = sum(
                    (event.duration or timedelta(0)).total_seconds()
                    for event in self.degradation_events
                    if event.duration
                )
                self.stats['average_degradation_time'] = total_degradation_time / len(self.degradation_events)
            
            logger.debug(f"Degradation statistics: {self.stats}")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def _cleanup_old_events(self):
        """Clean up old degradation events"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.config['metrics_retention'])
            
            # Remove old events
            self.degradation_events = [
                event for event in self.degradation_events
                if event.timestamp > cutoff_time
            ]
            
        except Exception as e:
            logger.error(f"Error cleaning up old events: {e}")
    
    async def get_degradation_status(self) -> Dict[str, Any]:
        """Get current degradation status"""
        try:
            return {
                'current_level': self.current_level.value,
                'service_status': {
                    service: status.value
                    for service, status in self.service_status.items()
                },
                'system_metrics': {
                    'health_score': self.system_metrics.health_score if self.system_metrics else 0.0,
                    'cpu_usage': self.system_metrics.cpu_usage if self.system_metrics else 0.0,
                    'memory_usage': self.system_metrics.memory_usage if self.system_metrics else 0.0,
                    'error_rate': self.system_metrics.error_rate if self.system_metrics else 0.0,
                    'response_time': self.system_metrics.response_time if self.system_metrics else 0.0
                },
                'statistics': self.stats,
                'recent_events': [
                    {
                        'event_id': event.event_id,
                        'trigger_type': event.trigger_type.value,
                        'from_level': event.from_level.value,
                        'to_level': event.to_level.value,
                        'timestamp': event.timestamp.isoformat(),
                        'reason': event.reason,
                        'resolved': event.resolved
                    }
                    for event in self.degradation_events[-10:]  # Last 10 events
                ]
            }
        except Exception as e:
            logger.error(f"Error getting degradation status: {e}")
            return {'error': str(e)}


# Global degraded mode manager instance
degraded_mode_manager = DegradedModeManager()


async def get_degradation_status() -> Dict[str, Any]:
    """Get current degradation status"""
    try:
        return await degraded_mode_manager.get_degradation_status()
    except Exception as e:
        logger.error(f"Error getting degradation status: {e}")
        return {'error': str(e)}


async def set_degradation_level(level: str, trigger_type: str = "manual", reason: str = "Manual intervention") -> str:
    """Set degradation level"""
    try:
        # Convert strings to enums
        level_enum = DegradationLevel(float(level))
        trigger_enum = TriggerType(trigger_type)
        
        success = await degraded_mode_manager.set_degradation_level(level_enum, trigger_enum, reason)
        
        if success:
            return f"Degradation level set to {level} successfully"
        else:
            return f"Failed to set degradation level to {level}"
            
    except Exception as e:
        logger.error(f"Error setting degradation level: {e}")
        return f"Error setting degradation level: {e}"


async def get_service_status(service_name: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific service"""
    try:
        status = degraded_mode_manager.service_status.get(service_name)
        if status:
            return {
                'service_name': service_name,
                'status': status.value,
                'priority': degraded_mode_manager.services.get(service_name, ServiceConfig("", 1, DegradationLevel.FULL, DegradationLevel.FULL, {}, [], {})).priority
            }
        return None
    except Exception as e:
        logger.error(f"Error getting service status: {e}")
        return None


async def get_all_service_status() -> Dict[str, Any]:
    """Get status of all services"""
    try:
        return {
            service_name: {
                'status': status.value,
                'priority': degraded_mode_manager.services.get(service_name, ServiceConfig("", 1, DegradationLevel.FULL, DegradationLevel.FULL, {}, [], {})).priority
            }
            for service_name, status in degraded_mode_manager.service_status.items()
        }
    except Exception as e:
        logger.error(f"Error getting all service status: {e}")
        return {}


# Initialize degraded mode manager
async def initialize_degraded_mode():
    """Initialize degraded mode manager"""
    try:
        await degraded_mode_manager.start()
        logger.info("Degraded mode manager initialized")
        return "Degraded mode manager initialized"
    except Exception as e:
        logger.error(f"Error initializing degraded mode manager: {e}")
        return f"Error initializing degraded mode manager: {e}"


# Cleanup function
async def cleanup_degraded_mode():
    """Cleanup degraded mode manager"""
    try:
        await degraded_mode_manager.stop()
        logger.info("Degraded mode manager cleaned up")
        return "Degraded mode manager cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up degraded mode manager: {e}")
        return f"Error cleaning up degraded mode manager: {e}"
