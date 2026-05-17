"""
Production-grade Observability System for Mary V5
Structured logging, request correlation, and comprehensive monitoring
"""

import os
import json
import uuid
import time
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum

from app.config import settings


class LogLevel(Enum):
    """Log levels for structured logging"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class LogEvent:
    """Structured log event"""
    timestamp: datetime
    level: LogLevel
    message: str
    correlation_id: str
    request_id: str
    user_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    method: Optional[str]
    path: Optional[str]
    status_code: Optional[int]
    latency_ms: Optional[float]
    error_details: Optional[Dict[str, Any]]
    tags: Dict[str, str]
    metadata: Dict[str, Any]


@dataclass
class MetricEvent:
    """Metric event data"""
    name: str
    type: MetricType
    value: Union[int, float]
    labels: Dict[str, str]
    timestamp: datetime
    help_text: Optional[str] = None


class RequestCorrelator:
    """Request correlation and tracking"""
    
    def __init__(self):
        self.active_requests = {}
        self.request_timeline = {}
    
    def generate_request_id(self) -> str:
        """Generate unique request ID"""
        return str(uuid.uuid4())
    
    def generate_correlation_id(self) -> str:
        """Generate unique correlation ID"""
        return str(uuid.uuid4())
    
    def start_request(self, request_id: str, correlation_id: str, method: str, path: str, source_ip: str):
        """Start tracking a request"""
        self.active_requests[request_id] = {
            "correlation_id": correlation_id,
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "start_time": time.time(),
            "start_datetime": datetime.utcnow()
        }
        
        # Add to timeline
        if correlation_id not in self.request_timeline:
            self.request_timeline[correlation_id] = []
        
        self.request_timeline[correlation_id].append({
            "request_id": request_id,
            "event": "start",
            "timestamp": datetime.utcnow(),
            "method": method,
            "path": path
        })
    
    def end_request(self, request_id: str, status_code: int, response_size: int = 0):
        """End tracking a request"""
        if request_id not in self.active_requests:
            return
        
        request_data = self.active_requests[request_id]
        end_time = time.time()
        latency_ms = (end_time - request_data["start_time"]) * 1000
        
        # Update request data
        request_data.update({
            "end_time": end_time,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "response_size": response_size
        })
        
        # Add to timeline
        correlation_id = request_data["correlation_id"]
        self.request_timeline[correlation_id].append({
            "request_id": request_id,
            "event": "end",
            "timestamp": datetime.utcnow(),
            "status_code": status_code,
            "latency_ms": latency_ms
        })
        
        # Clean up old requests (keep last 1000 per correlation)
        if len(self.request_timeline[correlation_id]) > 1000:
            self.request_timeline[correlation_id] = self.request_timeline[correlation_id][-1000:]
        
        # Remove from active requests
        del self.active_requests[request_id]
        
        return request_data
    
    def get_request_data(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get request tracking data"""
        return self.active_requests.get(request_id)
    
    def get_correlation_timeline(self, correlation_id: str) -> List[Dict[str, Any]]:
        """Get timeline for correlation ID"""
        return self.request_timeline.get(correlation_id, [])


class StructuredLogger:
    """Structured JSON logger with correlation support"""
    
    def __init__(self):
        self.service_name = "mary-v5"
        self.environment = settings.ENVIRONMENT
        self.version = settings.VERSION
        self.correlator = RequestCorrelator()
        self.log_buffer = []
        self.buffer_size = int(os.getenv("LOG_BUFFER_SIZE", "100"))
        self.flush_interval = int(os.getenv("LOG_FLUSH_INTERVAL", "5"))
        self.last_flush = time.time()
    
    def _create_log_event(self, level: LogLevel, message: str, **kwargs) -> LogEvent:
        """Create structured log event"""
        return LogEvent(
            timestamp=datetime.utcnow(),
            level=level,
            message=message,
            correlation_id=kwargs.get("correlation_id", ""),
            request_id=kwargs.get("request_id", ""),
            user_id=kwargs.get("user_id"),
            source_ip=kwargs.get("source_ip"),
            user_agent=kwargs.get("user_agent"),
            method=kwargs.get("method"),
            path=kwargs.get("path"),
            status_code=kwargs.get("status_code"),
            latency_ms=kwargs.get("latency_ms"),
            error_details=kwargs.get("error_details"),
            tags=kwargs.get("tags", {}),
            metadata=kwargs.get("metadata", {})
        )
    
    def _write_log(self, log_event: LogEvent):
        """Write log event to output"""
        log_data = {
            "timestamp": log_event.timestamp.isoformat(),
            "level": log_event.level.value,
            "service": self.service_name,
            "environment": self.environment,
            "version": self.version,
            "message": log_event.message,
            "correlation_id": log_event.correlation_id,
            "request_id": log_event.request_id,
            "user_id": log_event.user_id,
            "source_ip": log_event.source_ip,
            "user_agent": log_event.user_agent,
            "method": log_event.method,
            "path": log_event.path,
            "status_code": log_event.status_code,
            "latency_ms": log_event.latency_ms,
            "error_details": log_event.error_details,
            "tags": log_event.tags,
            "metadata": log_event.metadata
        }
        
        # Remove None values
        log_data = {k: v for k, v in log_data.items() if v is not None}
        
        # Output to stdout (can be configured for file/external service)
        print(json.dumps(log_data))
        
        # Add to buffer for batch processing
        self.log_buffer.append(log_data)
        
        # Flush if buffer is full or time interval passed
        current_time = time.time()
        if (len(self.log_buffer) >= self.buffer_size or 
            current_time - self.last_flush >= self.flush_interval):
            self._flush_buffer()
    
    def _flush_buffer(self):
        """Flush log buffer to external systems"""
        if not self.log_buffer:
            return
        
        try:
            # Here you could send to external logging service
            # e.g., Elasticsearch, Logstash, CloudWatch, etc.
            # For now, we'll just clear the buffer
            self.log_buffer.clear()
            self.last_flush = time.time()
        except Exception as e:
            print(f"Failed to flush log buffer: {e}")
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        log_event = self._create_log_event(LogLevel.DEBUG, message, **kwargs)
        self._write_log(log_event)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        log_event = self._create_log_event(LogLevel.INFO, message, **kwargs)
        self._write_log(log_event)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        log_event = self._create_log_event(LogLevel.WARNING, message, **kwargs)
        self._write_log(log_event)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        log_event = self._create_log_event(LogLevel.ERROR, message, **kwargs)
        self._write_log(log_event)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        log_event = self._create_log_event(LogLevel.CRITICAL, message, **kwargs)
        self._write_log(log_event)
    
    def log_request(self, method: str, path: str, status_code: int, 
                   latency_ms: float, source_ip: str = None, user_id: str = None,
                   correlation_id: str = None, request_id: str = None, **kwargs):
        """Log HTTP request"""
        self.info(
            "HTTP request completed",
            method=method,
            path=path,
            status_code=status_code,
            latency_ms=latency_ms,
            source_ip=source_ip,
            user_id=user_id,
            correlation_id=correlation_id,
            request_id=request_id,
            tags={"type": "http_request"},
            **kwargs
        )
    
    def log_threat_event(self, threat_event, correlation_id: str = None, **kwargs):
        """Log security threat event"""
        self.critical(
            f"Security threat detected: {threat_event.attack_type.value}",
            correlation_id=correlation_id,
            source_ip=threat_event.source_ip,
            tags={"type": "security_threat", "attack_type": threat_event.attack_type.value},
            metadata={
                "threat_level": threat_event.threat_level.value,
                "attack_type": threat_event.attack_type.value,
                "fingerprint": threat_event.fingerprint,
                "blocked": threat_event.blocked,
                "duration_minutes": threat_event.duration_minutes,
                "details": threat_event.details
            },
            **kwargs
        )
    
    def log_authentication_event(self, event_type: str, username: str = None,
                            source_ip: str = None, success: bool = None,
                            correlation_id: str = None, **kwargs):
        """Log authentication event"""
        level = LogLevel.INFO if success else LogLevel.WARNING
        self.log(
            level,
            f"Authentication {event_type}",
            correlation_id=correlation_id,
            source_ip=source_ip,
            tags={"type": "authentication", "event": event_type},
            metadata={
                "username": username,
                "success": success,
                "event_type": event_type
            },
            **kwargs
        )


class MetricsCollector:
    """Prometheus-compatible metrics collector"""
    
    def __init__(self):
        self.metrics = {}
        self.counters = {}
        self.gauges = {}
        self.histograms = {}
    
    def increment_counter(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Increment counter metric"""
        key = self._create_metric_key(name, labels)
        if key not in self.counters:
            self.counters[key] = 0
        self.counters[key] += value
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set gauge metric"""
        key = self._create_metric_key(name, labels)
        self.gauges[key] = value
    
    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe histogram metric"""
        key = self._create_metric_key(name, labels)
        if key not in self.histograms:
            self.histograms[key] = []
        self.histograms[key].append(value)
        
        # Keep only last 1000 observations
        if len(self.histograms[key]) > 1000:
            self.histograms[key] = self.histograms[key][-1000:]
    
    def _create_metric_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Create metric key with labels"""
        if not labels:
            return name
        
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        metrics_lines = []
        
        # Counters
        for key, value in self.counters.items():
            metrics_lines.append(f"# TYPE {key} counter")
            metrics_lines.append(f"{key} {value}")
        
        # Gauges
        for key, value in self.gauges.items():
            metrics_lines.append(f"# TYPE {key} gauge")
            metrics_lines.append(f"{key} {value}")
        
        # Histograms
        for key, values in self.histograms.items():
            if not values:
                continue
            
            metrics_lines.append(f"# TYPE {key} histogram")
            metrics_lines.append(f"{key}_count {len(values)}")
            metrics_lines.append(f"{key}_sum {sum(values)}")
            
            # Calculate quantiles
            sorted_values = sorted(values)
            n = len(sorted_values)
            if n > 0:
                for quantile in [0.5, 0.9, 0.95, 0.99]:
                    index = int(quantile * n)
                    if index >= n:
                        index = n - 1
                    metrics_lines.append(f"{key}_{int(quantile*100)}quantile {sorted_values[index]}")
        
        return "\n".join(metrics_lines)
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()


class TelemetryManager:
    """Comprehensive telemetry management"""
    
    def __init__(self):
        self.logger = StructuredLogger()
        self.metrics = MetricsCollector()
        self.correlator = RequestCorrelator()
        
        # Telemetry configuration
        self.enabled = os.getenv("TELEMETRY_ENABLED", "true").lower() == "true"
        self.detailed_logging = os.getenv("DETAILED_LOGGING", "false").lower() == "true"
    
    def track_request_start(self, method: str, path: str, source_ip: str) -> tuple:
        """Track request start"""
        if not self.enabled:
            return "", ""
        
        request_id = self.correlator.generate_request_id()
        correlation_id = self.correlator.generate_correlation_id()
        
        self.correlator.start_request(request_id, correlation_id, method, path, source_ip)
        
        return request_id, correlation_id
    
    def track_request_end(self, request_id: str, status_code: int, response_size: int = 0):
        """Track request end"""
        if not self.enabled or not request_id:
            return
        
        request_data = self.correlator.end_request(request_id, status_code, response_size)
        
        if request_data:
            # Log request
            self.logger.log_request(
                method=request_data["method"],
                path=request_data["path"],
                status_code=status_code,
                latency_ms=request_data["latency_ms"],
                source_ip=request_data["source_ip"],
                correlation_id=request_data["correlation_id"],
                request_id=request_id
            )
            
            # Update metrics
            self.metrics.increment_counter("http_requests_total", labels={
                "method": request_data["method"],
                "path": request_data["path"],
                "status": str(status_code)
            })
            
            self.metrics.observe_histogram("http_request_duration_ms", 
                                     request_data["latency_ms"], labels={
                "method": request_data["method"],
                "path": request_data["path"]
            })
    
    def track_authentication_event(self, event_type: str, username: str = None,
                               source_ip: str = None, success: bool = None,
                               correlation_id: str = None):
        """Track authentication events"""
        if not self.enabled:
            return
        
        self.logger.log_authentication_event(
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            success=success,
            correlation_id=correlation_id
        )
        
        # Update metrics
        self.metrics.increment_counter("authentication_events_total", labels={
            "event": event_type,
            "success": str(success).lower() if success is not None else "unknown"
        })
    
    def track_threat_event(self, threat_event, correlation_id: str = None):
        """Track threat events"""
        if not self.enabled:
            return
        
        self.logger.log_threat_event(threat_event, correlation_id)
        
        # Update metrics
        self.metrics.increment_counter("security_threats_total", labels={
            "attack_type": threat_event.attack_type.value,
            "threat_level": threat_event.threat_level.value,
            "blocked": str(threat_event.blocked).lower()
        })
    
    def get_metrics_endpoint(self) -> str:
        """Get Prometheus metrics"""
        if not self.enabled:
            return "# Metrics disabled"
        
        return self.metrics.get_prometheus_metrics()


# Global telemetry manager instance
telemetry = TelemetryManager()


# Utility functions
def generate_request_id() -> str:
    """Generate unique request ID"""
    return telemetry.correlator.generate_request_id()


def generate_correlation_id() -> str:
    """Generate unique correlation ID"""
    return telemetry.correlator.generate_correlation_id()


def track_request_start(method: str, path: str, source_ip: str) -> tuple:
    """Track request start"""
    return telemetry.track_request_start(method, path, source_ip)


def track_request_end(request_id: str, status_code: int, response_size: int = 0):
    """Track request end"""
    telemetry.track_request_end(request_id, status_code, response_size)


async def track_authentication_event(event_type: str, username: str = None,
                                source_ip: str = None, success: bool = None,
                                correlation_id: str = None):
    """Track authentication events"""
    telemetry.track_authentication_event(event_type, username, source_ip, success, correlation_id)


async def track_threat_event(threat_event, correlation_id: str = None):
    """Track threat events"""
    telemetry.track_threat_event(threat_event, correlation_id)


def get_prometheus_metrics() -> str:
    """Get Prometheus metrics"""
    return telemetry.get_metrics_endpoint()


def is_telemetry_enabled() -> bool:
    """Check if telemetry is enabled"""
    return telemetry.enabled
