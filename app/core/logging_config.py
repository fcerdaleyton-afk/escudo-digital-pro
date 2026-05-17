"""
MARY V5 SHIELD CORE - Advanced Logging Configuration
Structured JSON logging with correlation IDs and async-safe operations
"""

import os
import sys
import json
import time
import uuid
import logging
import logging.handlers
import threading
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import asyncio
from concurrent.futures import ThreadPoolExecutor
import queue

from app.core.dependencies import logger


class LogLevel(Enum):
    """Log levels with numeric values"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(Enum):
    """Log categories for better organization"""
    SECURITY = "security"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    API = "api"
    DATABASE = "database"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    THREAT = "threat"
    MIDDLEWARE = "middleware"
    ENTERPRISE = "enterprise"


@dataclass
class LogContext:
    """Log context with correlation information"""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    service_name: str = "mary-v5"
    service_version: str = "2.0.0"
    environment: str = "production"
    host: str = ""
    process_id: int = field(default_factory=os.getpid)
    thread_id: int = field(default_factory=lambda: threading.get_ident())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class StructuredLogEntry:
    """Structured log entry with full context"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    level: LogLevel = LogLevel.INFO
    category: LogCategory = LogCategory.SYSTEM
    message: str = ""
    context: LogContext = field(default_factory=LogContext)
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    duration_ms: Optional[float] = None
    stack_trace: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    function_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = {
            "timestamp": self.timestamp.isoformat() + "Z",
            "level": self.level.value,
            "category": self.category.value,
            "message": self.message,
            "context": self.context.to_dict(),
            "details": self.details,
            "tags": self.tags
        }
        
        if self.duration_ms is not None:
            data["duration_ms"] = self.duration_ms
        
        if self.stack_trace:
            data["stack_trace"] = self.stack_trace
        
        if self.source_file:
            data["source"] = {
                "file": self.source_file,
                "line": self.source_line,
                "function": self.function_name
            }
        
        return data


class AsyncLogHandler:
    """Async-safe log handler with background processing"""
    
    def __init__(self, max_queue_size: int = 10000):
        self.max_queue_size = max_queue_size
        self.log_queue = queue.Queue(maxsize=max_queue_size)
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="log-processor")
        self.processing = False
        self.stats = {
            "logs_queued": 0,
            "logs_processed": 0,
            "logs_dropped": 0,
            "processing_errors": 0
        }
    
    def start_processing(self):
        """Start background log processing"""
        if not self.processing:
            self.processing = True
            self.executor.submit(self._process_logs)
    
    def stop_processing(self):
        """Stop background log processing"""
        self.processing = False
        self.executor.shutdown(wait=True)
    
    def emit_log(self, log_entry: StructuredLogEntry):
        """Emit log entry for async processing"""
        try:
            self.log_queue.put_nowait(log_entry)
            self.stats["logs_queued"] += 1
        except queue.Full:
            self.stats["logs_dropped"] += 1
    
    def _process_logs(self):
        """Process logs in background thread"""
        while self.processing:
            try:
                # Get log entry with timeout
                log_entry = self.log_queue.get(timeout=1.0)
                
                # Process log entry
                self._write_log(log_entry)
                self.stats["logs_processed"] += 1
                
                self.log_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.stats["processing_errors"] += 1
                print(f"Log processing error: {e}", file=sys.stderr)
    
    def _write_log(self, log_entry: StructuredLogEntry):
        """Write log entry to output"""
        # Convert to JSON
        log_data = log_entry.to_dict()
        log_json = json.dumps(log_data, default=str, ensure_ascii=False)
        
        # Write to appropriate output based on level
        if log_entry.level in [LogLevel.ERROR, LogLevel.CRITICAL]:
            print(log_json, file=sys.stderr)
        else:
            print(log_json, file=sys.stdout)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get handler statistics"""
        return {
            "queue_size": self.log_queue.qsize(),
            "max_queue_size": self.max_queue_size,
            "processing": self.processing,
            **self.stats
        }


class CorrelationManager:
    """Manages correlation IDs and request tracing"""
    
    def __init__(self):
        self.enabled = os.getenv("CORRELATION_MANAGER_ENABLED", "true").lower() == "true"
        
        # Thread-local storage for context
        self._local = threading.local()
        
        # Correlation ID storage
        self.active_correlations = {}
        self.correlation_timeout = timedelta(hours=1)
        
        logger.info("Correlation manager initialized", enabled=self.enabled)
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for current context"""
        if not self.enabled:
            return
        
        self._local.correlation_id = correlation_id
        self.active_correlations[correlation_id] = datetime.utcnow()
        
        # Clean up old correlations
        self._cleanup_correlations()
    
    def get_correlation_id(self) -> str:
        """Get correlation ID for current context"""
        if not self.enabled:
            return str(uuid.uuid4())
        
        correlation_id = getattr(self._local, "correlation_id", None)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            self.set_correlation_id(correlation_id)
        
        return correlation_id
    
    def set_request_id(self, request_id: str):
        """Set request ID for current context"""
        if self.enabled:
            self._local.request_id = request_id
    
    def get_request_id(self) -> Optional[str]:
        """Get request ID for current context"""
        return getattr(self._local, "request_id", None) if self.enabled else None
    
    def set_user_id(self, user_id: str):
        """Set user ID for current context"""
        if self.enabled:
            self._local.user_id = user_id
    
    def get_user_id(self) -> Optional[str]:
        """Get user ID for current context"""
        return getattr(self._local, "user_id", None) if self.enabled else None
    
    def set_session_id(self, session_id: str):
        """Set session ID for current context"""
        if self.enabled:
            self._local.session_id = session_id
    
    def get_session_id(self) -> Optional[str]:
        """Get session ID for current context"""
        return getattr(self._local, "session_id", None) if self.enabled else None
    
    def create_context(self) -> LogContext:
        """Create log context with current values"""
        if not self.enabled:
            return LogContext()
        
        context = LogContext(
            correlation_id=self.get_correlation_id(),
            request_id=self.get_request_id(),
            user_id=self.get_user_id(),
            session_id=self.get_session_id()
        )
        
        return context
    
    def _cleanup_correlations(self):
        """Clean up old correlation IDs"""
        current_time = datetime.utcnow()
        expired_ids = [
            correlation_id for correlation_id, timestamp in self.active_correlations.items()
            if current_time - timestamp > self.correlation_timeout
        ]
        
        for correlation_id in expired_ids:
            del self.active_correlations[correlation_id]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation manager statistics"""
        return {
            "enabled": self.enabled,
            "active_correlations": len(self.active_correlations),
            "correlation_timeout_hours": self.correlation_timeout.total_seconds() / 3600
        }


class StructuredLogger:
    """Advanced structured logger with async processing"""
    
    def __init__(self, name: str = "mary-v5"):
        self.name = name
        self.enabled = os.getenv("STRUCTURED_LOGGER_ENABLED", "true").lower() == "true"
        
        # Log level configuration
        self.min_level = LogLevel(os.getenv("LOG_LEVEL", "INFO").upper())
        
        # Async handler
        self.async_handler = AsyncLogHandler()
        
        # Correlation manager
        self.correlation_manager = CorrelationManager()
        
        # Log formatters
        self.formatters = self._create_formatters()
        
        # Output configuration
        self.outputs = self._configure_outputs()
        
        # Statistics
        self.logger_stats = {
            "logs_created": 0,
            "logs_by_level": defaultdict(int),
            "logs_by_category": defaultdict(int)
        }
        
        # Start async processing
        if self.enabled:
            self.async_handler.start_processing()
        
        logger.info(f"Structured logger initialized: {name}", enabled=self.enabled)
    
    def _create_formatters(self) -> Dict[str, Any]:
        """Create log formatters"""
        return {
            "json_formatter": lambda entry: json.dumps(entry.to_dict(), default=str, ensure_ascii=False),
            "pretty_formatter": lambda entry: self._format_pretty(entry)
        }
    
    def _format_pretty(self, entry: StructuredLogEntry) -> str:
        """Format log entry for human reading"""
        timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level = entry.level.value.ljust(8)
        category = entry.category.value.ljust(12)
        
        parts = [
            f"[{timestamp}]",
            f"{level}",
            f"{category}",
            f"[{entry.context.correlation_id[:8]}]",
            entry.message
        ]
        
        if entry.duration_ms:
            parts.append(f"({entry.duration_ms:.2f}ms)")
        
        if entry.details:
            parts.append(f"| {json.dumps(entry.details, default=str)}")
        
        return " ".join(parts)
    
    def _configure_outputs(self) -> List[str]:
        """Configure log outputs"""
        output_config = os.getenv("LOG_OUTPUTS", "json,console").split(",")
        return [output.strip() for output in output_config if output.strip()]
    
    def _should_log(self, level: LogLevel) -> bool:
        """Check if log level should be logged"""
        level_values = {
            LogLevel.DEBUG: 10,
            LogLevel.INFO: 20,
            LogLevel.WARNING: 30,
            LogLevel.ERROR: 40,
            LogLevel.CRITICAL: 50
        }
        
        return level_values.get(level, 20) >= level_values.get(self.min_level, 20)
    
    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM, 
             details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log debug message"""
        self._log(LogLevel.DEBUG, message, category, details, tags, **kwargs)
    
    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM,
            details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log info message"""
        self._log(LogLevel.INFO, message, category, details, tags, **kwargs)
    
    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM,
               details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log warning message"""
        self._log(LogLevel.WARNING, message, category, details, tags, **kwargs)
    
    def error(self, message: str, category: LogCategory = LogCategory.SYSTEM,
              details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log error message"""
        self._log(LogLevel.ERROR, message, category, details, tags, **kwargs)
    
    def critical(self, message: str, category: LogCategory = LogCategory.SYSTEM,
                 details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log critical message"""
        self._log(LogLevel.CRITICAL, message, category, details, tags, **kwargs)
    
    def security(self, message: str, details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log security event"""
        self._log(LogLevel.INFO, message, LogCategory.SECURITY, details, tags, **kwargs)
    
    def audit(self, message: str, details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log audit event"""
        self._log(LogLevel.INFO, message, LogCategory.AUDIT, details, tags, **kwargs)
    
    def threat(self, message: str, details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log threat event"""
        self._log(LogLevel.WARNING, message, LogCategory.THREAT, details, tags, **kwargs)
    
    def performance(self, message: str, duration_ms: float = None, 
                   details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Log performance event"""
        self._log(LogLevel.INFO, message, LogCategory.PERFORMANCE, details, tags, 
                 duration_ms=duration_ms, **kwargs)
    
    def _log(self, level: LogLevel, message: str, category: LogCategory = LogCategory.SYSTEM,
             details: Dict[str, Any] = None, tags: List[str] = None, **kwargs):
        """Internal logging method"""
        if not self.enabled or not self._should_log(level):
            return
        
        # Create log entry
        log_entry = StructuredLogEntry(
            level=level,
            category=category,
            message=message,
            context=self.correlation_manager.create_context(),
            details=details or {},
            tags=tags or [],
            **kwargs
        )
        
        # Add source information if available
        if kwargs.get("include_source", False):
            import inspect
            frame = inspect.currentframe().f_back
            log_entry.source_file = frame.f_code.co_filename
            log_entry.source_line = frame.f_lineno
            log_entry.function_name = frame.f_code.co_name
        
        # Update statistics
        self.logger_stats["logs_created"] += 1
        self.logger_stats["logs_by_level"][level.value] += 1
        self.logger_stats["logs_by_category"][category.value] += 1
        
        # Send to async handler
        self.async_handler.emit_log(log_entry)
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for current context"""
        self.correlation_manager.set_correlation_id(correlation_id)
    
    def get_correlation_id(self) -> str:
        """Get correlation ID for current context"""
        return self.correlation_manager.get_correlation_id()
    
    def set_request_id(self, request_id: str):
        """Set request ID for current context"""
        self.correlation_manager.set_request_id(request_id)
    
    def set_user_id(self, user_id: str):
        """Set user ID for current context"""
        self.correlation_manager.set_user_id(user_id)
    
    def set_session_id(self, session_id: str):
        """Set session ID for current context"""
        self.correlation_manager.set_session_id(session_id)
    
    def get_logger_stats(self) -> Dict[str, Any]:
        """Get logger statistics"""
        return {
            "enabled": self.enabled,
            "min_level": self.min_level.value,
            "outputs": self.outputs,
            **self.logger_stats,
            "async_handler": self.async_handler.get_stats(),
            "correlation_manager": self.correlation_manager.get_stats()
        }
    
    def shutdown(self):
        """Shutdown logger"""
        if self.enabled:
            self.async_handler.stop_processing()


class LoggingMiddleware:
    """Middleware for automatic request logging"""
    
    def __init__(self, logger: StructuredLogger):
        self.logger = logger
        self.enabled = os.getenv("LOGGING_MIDDLEWARE_ENABLED", "true").lower() == "true"
        
        # Request tracking
        self.request_stats = {
            "requests_logged": 0,
            "average_response_time": 0.0,
            "requests_by_status": defaultdict(int)
        }
    
    async def log_request(self, method: str, path: str, status_code: int, 
                        duration_ms: float, client_ip: str = None,
                        user_id: str = None, request_id: str = None):
        """Log HTTP request"""
        if not self.enabled:
            return
        
        # Set correlation context
        if request_id:
            self.logger.set_request_id(request_id)
        if user_id:
            self.logger.set_user_id(user_id)
        
        # Determine log level based on status code
        if status_code >= 500:
            level = LogLevel.ERROR
            category = LogCategory.SYSTEM
        elif status_code >= 400:
            level = LogLevel.WARNING
            category = LogCategory.API
        else:
            level = LogLevel.INFO
            category = LogCategory.API
        
        # Log request
        self.logger._log(
            level=level,
            message=f"{method} {path} {status_code}",
            category=category,
            details={
                "method": method,
                "path": path,
                "status_code": status_code,
                "client_ip": client_ip,
                "request_id": request_id
            },
            tags=["http_request"],
            duration_ms=duration_ms
        )
        
        # Update statistics
        self.request_stats["requests_logged"] += 1
        self.request_stats["requests_by_status"][status_code] += 1
        
        # Update average response time
        total_requests = self.request_stats["requests_logged"]
        current_avg = self.request_stats["average_response_time"]
        self.request_stats["average_response_time"] = (
            (current_avg * (total_requests - 1) + duration_ms) / total_requests
        )
    
    def get_request_stats(self) -> Dict[str, Any]:
        """Get request logging statistics"""
        return {
            "enabled": self.enabled,
            **self.request_stats
        }


# Global structured logger instance
structured_logger = StructuredLogger("mary-v5")
logging_middleware = LoggingMiddleware(structured_logger)


def get_structured_logger(name: str = "mary-v5") -> StructuredLogger:
    """Get structured logger instance"""
    return StructuredLogger(name)


def get_logging_middleware() -> LoggingMiddleware:
    """Get logging middleware"""
    return logging_middleware


def configure_logging():
    """Configure Python logging to use structured logger"""
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add structured logger handler
    class StructuredLogHandler(logging.Handler):
        def emit(self, record):
            # Convert to structured log
            level = LogLevel(record.levelname)
            message = record.getMessage()
            
            # Extract details from record
            details = {}
            if hasattr(record, 'details'):
                details.update(record.details)
            
            # Log to structured logger
            structured_logger._log(level, message, LogCategory.SYSTEM, details)
    
    structured_handler = StructuredLogHandler()
    root_logger.addHandler(structured_handler)


# Initialize logging configuration
configure_logging()
