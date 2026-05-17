"""
MARY V5 SHIELD CORE - Circuit Breaker System
Prevent cascading failures with auto-recovery and timeout isolation
"""

import os
import time
import asyncio
import random
from typing import Dict, List, Optional, Any, Callable, Union, TypeVar
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading
import weakref

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, calls fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


class FailureType(Enum):
    """Types of failures"""
    TIMEOUT = "timeout"
    EXCEPTION = "exception"
    RATE_LIMIT = "rate_limit"
    NETWORK_ERROR = "network_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    AUTHENTICATION_ERROR = "authentication_error"
    VALIDATION_ERROR = "validation_error"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    name: str
    failure_threshold: int = 5          # Failures before opening
    timeout: float = 60.0                # Seconds to wait before trying again
    recovery_timeout: float = 30.0      # Half-open timeout
    max_retries: int = 3                # Maximum retry attempts
    retry_delay: float = 1.0            # Delay between retries
    jitter: float = 0.1                 # Random jitter for retries
    expected_exception: Type[Exception] = Exception
    fallback_function: Optional[Callable] = None
    metrics_enabled: bool = True
    timeout_seconds: Optional[float] = None  # Individual call timeout


@dataclass
class CircuitBreakerMetrics:
    """Circuit breaker metrics"""
    name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    timeout_calls: int = 0
    retry_calls: int = 0
    fallback_calls: int = 0
    state_changes: int = 0
    last_state_change: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    current_state: CircuitState = CircuitState.CLOSED
    failure_rate: float = 0.0
    average_response_time: float = 0.0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    
    def update_success(self, response_time: float):
        """Update metrics on successful call"""
        self.total_calls += 1
        self.successful_calls += 1
        self.response_times.append(response_time)
        self._calculate_derived_metrics()
    
    def update_failure(self, failure_type: FailureType):
        """Update metrics on failed call"""
        self.total_calls += 1
        self.failed_calls += 1
        self.last_failure = datetime.utcnow()
        self._calculate_derived_metrics()
    
    def update_timeout(self):
        """Update metrics on timeout"""
        self.total_calls += 1
        self.timeout_calls += 1
        self.failed_calls += 1
        self.last_failure = datetime.utcnow()
        self._calculate_derived_metrics()
    
    def update_retry(self):
        """Update metrics on retry"""
        self.retry_calls += 1
    
    def update_fallback(self):
        """Update metrics on fallback call"""
        self.fallback_calls += 1
    
    def update_state_change(self, new_state: CircuitState):
        """Update state change metrics"""
        self.state_changes += 1
        self.current_state = new_state
        self.last_state_change = datetime.utcnow()
    
    def _calculate_derived_metrics(self):
        """Calculate derived metrics"""
        if self.total_calls > 0:
            self.failure_rate = (self.failed_calls / self.total_calls) * 100
        
        if self.response_times:
            self.average_response_time = sum(self.response_times) / len(self.response_times)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "timeout_calls": self.timeout_calls,
            "retry_calls": self.retry_calls,
            "fallback_calls": self.fallback_calls,
            "state_changes": self.state_changes,
            "last_state_change": self.last_state_change.isoformat() if self.last_state_change else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "current_state": self.current_state.value,
            "failure_rate": round(self.failure_rate, 2),
            "average_response_time": round(self.average_response_time, 3)
        }


class CircuitBreakerError(Exception):
    """Base circuit breaker exception"""
    pass


class CircuitOpenError(CircuitBreakerError):
    """Raised when circuit is open"""
    pass


class CircuitTimeoutError(CircuitBreakerError):
    """Raised when call times out"""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation with async support and auto-recovery
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_calls = 0
        self.max_half_open_calls = 3  # Number of calls allowed in half-open state
        
        # Metrics
        self.metrics = CircuitBreakerMetrics(name=config.name)
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # Logger
        self.logger = get_structured_logger(f"circuit_breaker.{config.name}")
        
        # Event listeners
        self._state_change_listeners = []
        
        self.logger.info("Circuit breaker initialized", 
                        name=config.name,
                        failure_threshold=config.failure_threshold,
                        timeout=config.timeout)
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection
        """
        start_time = time.time()
        
        try:
            # Check if circuit is open
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._move_to_half_open()
                else:
                    self.metrics.update_failure(FailureType.SERVICE_UNAVAILABLE)
                    raise CircuitOpenError(f"Circuit {self.config.name} is open")
            
            # Execute the function
            result = await self._execute_with_timeout(func, *args, **kwargs)
            
            # Success - reset failure count
            if self.state == CircuitState.HALF_OPEN:
                self._move_to_closed()
            
            # Update metrics
            response_time = time.time() - start_time
            self.metrics.update_success(response_time)
            
            return result
            
        except asyncio.TimeoutError as e:
            self.metrics.update_timeout()
            self._handle_failure()
            raise CircuitTimeoutError(f"Call to {func.__name__} timed out") from e
            
        except Exception as e:
            # Check if this is an expected exception
            if isinstance(e, self.config.expected_exception):
                self.metrics.update_failure(self._classify_failure(e))
                self._handle_failure()
                raise
            else:
                # Unexpected exception - still count as failure
                self.metrics.update_failure(FailureType.EXCEPTION)
                self._handle_failure()
                raise
    
    async def _execute_with_timeout(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with timeout if configured"""
        if self.config.timeout_seconds:
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.config.timeout_seconds
                )
            except asyncio.TimeoutError:
                raise
        else:
            return await func(*args, **kwargs)
    
    def _classify_failure(self, exception: Exception) -> FailureType:
        """Classify the type of failure"""
        exception_type = type(exception).__name__.lower()
        
        if "timeout" in exception_type:
            return FailureType.TIMEOUT
        elif "connection" in exception_type or "network" in exception_type:
            return FailureType.NETWORK_ERROR
        elif "auth" in exception_type or "permission" in exception_type:
            return FailureType.AUTHENTICATION_ERROR
        elif "validation" in exception_type or "value" in exception_type:
            return FailureType.VALIDATION_ERROR
        elif "rate" in exception_type or "limit" in exception_type:
            return FailureType.RATE_LIMIT
        elif "service" in exception_type or "unavailable" in exception_type:
            return FailureType.SERVICE_UNAVAILABLE
        else:
            return FailureType.EXCEPTION
    
    def _handle_failure(self):
        """Handle a failure by updating state and metrics"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            
            if self.state == CircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self._move_to_open()
            elif self.state == CircuitState.HALF_OPEN:
                self._move_to_open()
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt to reset"""
        if self.last_failure_time is None:
            return True
        
        time_since_failure = datetime.utcnow() - self.last_failure_time
        return time_since_failure.total_seconds() >= self.config.timeout
    
    def _move_to_open(self):
        """Move circuit to open state"""
        old_state = self.state
        self.state = CircuitState.OPEN
        self.metrics.update_state_change(self.state)
        
        self._notify_state_change(old_state, self.state)
        
        self.logger.warning("Circuit breaker opened", 
                           name=self.config.name,
                           failure_count=self.failure_count,
                           timeout=self.config.timeout)
    
    def _move_to_half_open(self):
        """Move circuit to half-open state"""
        old_state = self.state
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0
        self.metrics.update_state_change(self.state)
        
        self._notify_state_change(old_state, self.state)
        
        self.logger.info("Circuit breaker moved to half-open", 
                        name=self.config.name)
    
    def _move_to_closed(self):
        """Move circuit to closed state"""
        old_state = self.state
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.half_open_calls = 0
        self.metrics.update_state_change(self.state)
        
        self._notify_state_change(old_state, self.state)
        
        self.logger.info("Circuit breaker closed", 
                        name=self.config.name)
    
    def _notify_state_change(self, old_state: CircuitState, new_state: CircuitState):
        """Notify listeners of state change"""
        for listener in self._state_change_listeners:
            try:
                listener(self.config.name, old_state, new_state)
            except Exception as e:
                self.logger.error("State change listener error", 
                                listener=str(listener),
                                error=str(e))
    
    def add_state_change_listener(self, listener: Callable[[str, CircuitState, CircuitState], None]):
        """Add listener for state changes"""
        self._state_change_listeners.append(listener)
    
    def remove_state_change_listener(self, listener: Callable[[str, CircuitState, CircuitState], None]):
        """Remove state change listener"""
        if listener in self._state_change_listeners:
            self._state_change_listeners.remove(listener)
    
    def get_state(self) -> CircuitState:
        """Get current circuit state"""
        return self.state
    
    def get_metrics(self) -> CircuitBreakerMetrics:
        """Get circuit breaker metrics"""
        return self.metrics
    
    def force_open(self):
        """Force circuit to open state"""
        with self._lock:
            self._move_to_open()
    
    def force_close(self):
        """Force circuit to closed state"""
        with self._lock:
            self._move_to_closed()
    
    def reset(self):
        """Reset circuit breaker to initial state"""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
            self.half_open_calls = 0
            self.metrics = CircuitBreakerMetrics(name=self.config.name)
            
            self.logger.info("Circuit breaker reset", name=self.config.name)


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers"""
    
    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()
        self.logger = get_structured_logger("circuit_breaker_registry")
    
    def create_circuit_breaker(self, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Create and register a circuit breaker"""
        with self._lock:
            if config.name in self._circuit_breakers:
                self.logger.warning("Circuit breaker already exists", name=config.name)
                return self._circuit_breakers[config.name]
            
            circuit_breaker = CircuitBreaker(config)
            self._circuit_breakers[config.name] = circuit_breaker
            
            self.logger.info("Circuit breaker registered", name=config.name)
            return circuit_breaker
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        with self._lock:
            return self._circuit_breakers.get(name)
    
    def list_circuit_breakers(self) -> List[str]:
        """List all circuit breaker names"""
        with self._lock:
            return list(self._circuit_breakers.keys())
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all circuit breakers"""
        with self._lock:
            return {
                name: cb.get_metrics().to_dict()
                for name, cb in self._circuit_breakers.items()
            }
    
    def force_all_open(self):
        """Force all circuit breakers to open state"""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.force_open()
        
        self.logger.warning("All circuit breakers forced open")
    
    def force_all_closed(self):
        """Force all circuit breakers to closed state"""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.force_close()
        
        self.logger.info("All circuit breakers forced closed")
    
    def reset_all(self):
        """Reset all circuit breakers"""
        with self._lock:
            for cb in self._circuit_breakers.values():
                cb.reset()
        
        self.logger.info("All circuit breakers reset")


class CircuitBreakerDecorator:
    """Decorator for circuit breaker functionality"""
    
    def __init__(self, 
                 name: str,
                 failure_threshold: int = 5,
                 timeout: float = 60.0,
                 recovery_timeout: float = 30.0,
                 max_retries: int = 3,
                 timeout_seconds: Optional[float] = None,
                 expected_exception: Type[Exception] = Exception):
        
        self.config = CircuitBreakerConfig(
            name=name,
            failure_threshold=failure_threshold,
            timeout=timeout,
            recovery_timeout=recovery_timeout,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            expected_exception=expected_exception
        )
        
        # Get or create circuit breaker
        self.circuit_breaker = circuit_breaker_registry.get_circuit_breaker(name)
        if self.circuit_breaker is None:
            self.circuit_breaker = circuit_breaker_registry.create_circuit_breaker(self.config)
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator implementation"""
        async def wrapper(*args, **kwargs):
            return await self.circuit_breaker.call(func, *args, **kwargs)
        
        return wrapper


class CircuitBreakerManager:
    """High-level circuit breaker manager"""
    
    def __init__(self):
        self.enabled = os.getenv("CIRCUIT_BREAKER_ENABLED", "true").lower() == "true"
        self.registry = circuit_breaker_registry
        self.logger = get_structured_logger("circuit_breaker_manager")
        
        # Default configurations
        self.default_configs = self._load_default_configs()
        
        # Auto-configuration
        asyncio.create_task(self._auto_configure())
        
        self.logger.info("Circuit breaker manager initialized", enabled=self.enabled)
    
    def _load_default_configs(self) -> Dict[str, CircuitBreakerConfig]:
        """Load default circuit breaker configurations"""
        return {
            "database": CircuitBreakerConfig(
                name="database",
                failure_threshold=5,
                timeout=60.0,
                recovery_timeout=30.0,
                max_retries=3,
                timeout_seconds=30.0
            ),
            "external_api": CircuitBreakerConfig(
                name="external_api",
                failure_threshold=3,
                timeout=120.0,
                recovery_timeout=60.0,
                max_retries=2,
                timeout_seconds=15.0
            ),
            "authentication": CircuitBreakerConfig(
                name="authentication",
                failure_threshold=5,
                timeout=30.0,
                recovery_timeout=15.0,
                max_retries=2,
                timeout_seconds=10.0
            ),
            "cache": CircuitBreakerConfig(
                name="cache",
                failure_threshold=10,
                timeout=30.0,
                recovery_timeout=10.0,
                max_retries=1,
                timeout_seconds=5.0
            ),
            "threat_intel": CircuitBreakerConfig(
                name="threat_intel",
                failure_threshold=3,
                timeout=180.0,
                recovery_timeout=90.0,
                max_retries=2,
                timeout_seconds=30.0
            )
        }
    
    async def _auto_configure(self):
        """Auto-configure circuit breakers based on security settings"""
        try:
            settings = await get_security_settings()
            
            if settings.circuit_breaker_enabled:
                # Update configurations based on settings
                for name, config in self.default_configs.items():
                    config.failure_threshold = settings.circuit_breaker_failure_threshold
                    config.timeout = settings.circuit_breaker_timeout
                    config.recovery_timeout = settings.circuit_breaker_recovery_timeout
                
                # Create circuit breakers
                for config in self.default_configs.values():
                    self.registry.create_circuit_breaker(config)
                
                self.logger.info("Circuit breakers auto-configured", 
                               count=len(self.default_configs))
        
        except Exception as e:
            self.logger.error("Failed to auto-configure circuit breakers", error=str(e))
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self.registry.get_circuit_breaker(name)
    
    def create_circuit_breaker(self, name: str, **kwargs) -> CircuitBreaker:
        """Create new circuit breaker"""
        config = CircuitBreakerConfig(name=name, **kwargs)
        return self.registry.create_circuit_breaker(config)
    
    def decorator(self, name: str, **kwargs) -> CircuitBreakerDecorator:
        """Create circuit breaker decorator"""
        return CircuitBreakerDecorator(name=name, **kwargs)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all circuit breakers"""
        return {
            "enabled": self.enabled,
            "circuit_breakers": self.registry.get_all_metrics(),
            "summary": self._calculate_summary_metrics()
        }
    
    def _calculate_summary_metrics(self) -> Dict[str, Any]:
        """Calculate summary metrics across all circuit breakers"""
        all_metrics = self.registry.get_all_metrics()
        
        if not all_metrics:
            return {}
        
        total_calls = sum(m["total_calls"] for m in all_metrics.values())
        total_failures = sum(m["failed_calls"] for m in all_metrics.values())
        total_timeouts = sum(m["timeout_calls"] for m in all_metrics.values())
        
        open_circuits = sum(1 for m in all_metrics.values() if m["current_state"] == "open")
        half_open_circuits = sum(1 for m in all_metrics.values() if m["current_state"] == "half_open")
        
        return {
            "total_circuit_breakers": len(all_metrics),
            "open_circuits": open_circuits,
            "half_open_circuits": half_open_circuits,
            "closed_circuits": len(all_metrics) - open_circuits - half_open_circuits,
            "total_calls": total_calls,
            "total_failures": total_failures,
            "total_timeouts": total_timeouts,
            "overall_failure_rate": round((total_failures / total_calls * 100) if total_calls > 0 else 0, 2)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all circuit breakers"""
        all_metrics = self.registry.get_all_metrics()
        
        health_status = {
            "healthy": True,
            "issues": [],
            "circuit_breakers": {}
        }
        
        for name, metrics in all_metrics.items():
            circuit_health = {
                "state": metrics["current_state"],
                "failure_rate": metrics["failure_rate"],
                "healthy": True
            }
            
            # Check if circuit has issues
            if metrics["current_state"] == "open":
                circuit_health["healthy"] = False
                health_status["healthy"] = False
                health_status["issues"].append(f"{name}: Circuit is open")
            elif metrics["failure_rate"] > 50:
                circuit_health["healthy"] = False
                health_status["healthy"] = False
                health_status["issues"].append(f"{name}: High failure rate ({metrics['failure_rate']}%)")
            
            health_status["circuit_breakers"][name] = circuit_health
        
        return health_status


# Global instances
circuit_breaker_registry = CircuitBreakerRegistry()
circuit_breaker_manager = CircuitBreakerManager()


def circuit_breaker(name: str, **kwargs) -> CircuitBreakerDecorator:
    """Circuit breaker decorator"""
    return circuit_breaker_manager.decorator(name, **kwargs)


async def get_circuit_breaker_metrics() -> Dict[str, Any]:
    """Get circuit breaker metrics"""
    return circuit_breaker_manager.get_all_metrics()


async def circuit_breaker_health_check() -> Dict[str, Any]:
    """Perform circuit breaker health check"""
    return await circuit_breaker_manager.health_check()
