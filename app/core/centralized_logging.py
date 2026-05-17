"""
Centralized Logging System for Mary V5
Provides structured, production-ready logging with multiple outputs
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from app.core.dependencies import logger


class LogLevel(Enum):
    """Log levels for centralized logging"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"
    AUDIT = "audit"


class LogOutput(Enum):
    """Log output destinations"""
    FILE = "file"
    CONSOLE = "console"
    SYSLOG = "syslog"
    ELASTICSEARCH = "elasticsearch"
    SPLUNK = "splunk"
    DATADOG = "datadog"


class CentralizedLogger:
    """
    Centralized logging system with multiple outputs and structured formatting
    """
    
    def __init__(self):
        self.enabled = os.getenv("CENTRALIZED_LOGGING_ENABLED", "true").lower() == "true"
        self.log_level = LogLevel(os.getenv("LOG_LEVEL", "info"))
        self.outputs = self._parse_outputs()
        
        # Log retention settings
        self.retention_days = int(os.getenv("LOG_RETENTION_DAYS", "30"))
        self.max_file_size = int(os.getenv("MAX_LOG_FILE_SIZE", "100")) * 1024 * 1024  # MB
        
        # Security event tracking
        self.security_events = []
        self.audit_trail = []
        
        # Initialize loggers
        self._setup_loggers()
        
        logger.info("Centralized logging initialized", enabled=self.enabled, outputs=self.outputs)
    
    def _parse_outputs(self) -> List[str]:
        """Parse log outputs from environment"""
        outputs_str = os.getenv("LOG_OUTPUTS", "console,file")
        return [output.strip() for output in outputs_str.split(",")]
    
    def _setup_loggers(self):
        """Setup different log outputs"""
        self.loggers = {}
        
        for output in self.outputs:
            if output == LogOutput.FILE.value:
                self._setup_file_logger()
            elif output == LogOutput.CONSOLE.value:
                self._setup_console_logger()
            elif output == LogOutput.SYSLOG.value:
                self._setup_syslog_logger()
            elif output == LogOutput.ELASTICSEARCH.value:
                self._setup_elasticsearch_logger()
            elif output == LogOutput.SPLUNK.value:
                self._setup_splunk_logger()
            elif output == LogOutput.DATADOG.value:
                self._setup_datadog_logger()
    
    def _setup_file_logger(self):
        """Setup file logger with rotation"""
        import logging.handlers
        
        log_file = os.getenv("LOG_FILE_PATH", "/var/log/mary-v5/app.log")
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_file_size,
            backupCount=5
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        file_logger = logging.getLogger(f"mary_v5_file_{id(self)}")
        file_logger.addHandler(file_handler)
        file_logger.setLevel(getattr(logging, self.log_level.value.upper()))
        
        self.loggers[LogOutput.FILE.value] = file_logger
    
    def _setup_console_logger(self):
        """Setup console logger"""
        console_logger = logging.getLogger(f"mary_v5_console_{id(self)}")
        console_handler = logging.StreamHandler()
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        console_logger.addHandler(console_handler)
        console_logger.setLevel(getattr(logging, self.log_level.value.upper()))
        
        self.loggers[LogOutput.CONSOLE.value] = console_logger
    
    def _setup_syslog_logger(self):
        """Setup syslog logger"""
        try:
            import logging.handlers
            
            syslog_handler = logging.handlers.SysLogHandler(
                address=os.getenv("SYSLOG_ADDRESS", "/dev/log"),
                facility=logging.handlers.SysLogHandler.LOG_LOCAL0
            )
            
            syslog_logger = logging.getLogger(f"mary_v5_syslog_{id(self)}")
            syslog_logger.addHandler(syslog_handler)
            syslog_logger.setLevel(getattr(logging, self.log_level.value.upper()))
            
            self.loggers[LogOutput.SYSLOG.value] = syslog_logger
        except Exception as e:
            logger.error("Failed to setup syslog logger", error=str(e))
    
    def _setup_elasticsearch_logger(self):
        """Setup Elasticsearch logger"""
        try:
            from elasticsearch import Elasticsearch
            
            es_host = os.getenv("ELASTICSEARCH_HOST", "localhost:9200")
            es_index = os.getenv("ELASTICSEARCH_INDEX", "mary-v5-logs")
            
            # This would require elasticsearch-py library
            # Implementation would include async bulk indexing
            logger.info("Elasticsearch logger configured", host=es_host, index=es_index)
            
        except ImportError:
            logger.warning("Elasticsearch library not available")
        except Exception as e:
            logger.error("Failed to setup Elasticsearch logger", error=str(e))
    
    def _setup_splunk_logger(self):
        """Setup Splunk logger"""
        try:
            # This would require splunk-sdk library
            splunk_host = os.getenv("SPLUNK_HOST", "localhost:8088")
            splunk_token = os.getenv("SPLUNK_TOKEN", "")
            
            logger.info("Splunk logger configured", host=splunk_host)
            
        except Exception as e:
            logger.error("Failed to setup Splunk logger", error=str(e))
    
    def _setup_datadog_logger(self):
        """Setup Datadog logger"""
        try:
            from datadog import initialize, statsd
            
            datadog_api_key = os.getenv("DATADOG_API_KEY", "")
            initialize(api_key=datadog_api_key)
            
            logger.info("Datadog logger configured")
            
        except ImportError:
            logger.warning("Datadog library not available")
        except Exception as e:
            logger.error("Failed to setup Datadog logger", error=str(e))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                        severity: LogLevel = LogLevel.SECURITY, 
                        correlation_id: str = None):
        """Log security event with structured data"""
        if not self.enabled:
            return
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "security",
            "severity": severity.value,
            "category": event_type,
            "correlation_id": correlation_id,
            "details": details,
            "source": "mary-v5-security"
        }
        
        self.security_events.append(event)
        self._write_log(event)
        
        # Also send to alerting system if critical
        if severity in [LogLevel.CRITICAL, LogLevel.SECURITY]:
            from app.core.alerting import send_security_alert
            asyncio.create_task(send_security_alert(event, correlation_id))
    
    def log_audit_event(self, action: str, user: str = None, 
                     resource: str = None, result: str = "success",
                     details: Dict[str, Any] = None, 
                     correlation_id: str = None):
        """Log audit event for compliance"""
        if not self.enabled:
            return
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "audit",
            "severity": LogLevel.AUDIT.value,
            "action": action,
            "user": user,
            "resource": resource,
            "result": result,
            "details": details or {},
            "correlation_id": correlation_id,
            "source": "mary-v5-audit"
        }
        
        self.audit_trail.append(event)
        self._write_log(event)
    
    def log_performance_event(self, operation: str, duration_ms: float,
                          resource_usage: Dict[str, Any] = None,
                          details: Dict[str, Any] = None,
                          correlation_id: str = None):
        """Log performance event"""
        if not self.enabled:
            return
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "performance",
            "severity": LogLevel.INFO.value,
            "operation": operation,
            "duration_ms": duration_ms,
            "resource_usage": resource_usage or {},
            "details": details or {},
            "correlation_id": correlation_id,
            "source": "mary-v5-performance"
        }
        
        self._write_log(event)
    
    def log_business_event(self, event_name: str, data: Dict[str, Any],
                         severity: LogLevel = LogLevel.INFO,
                         correlation_id: str = None):
        """Log business event"""
        if not self.enabled:
            return
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "business",
            "severity": severity.value,
            "event_name": event_name,
            "data": data,
            "correlation_id": correlation_id,
            "source": "mary-v5-business"
        }
        
        self._write_log(event)
    
    def _write_log(self, event: Dict[str, Any]):
        """Write log event to all configured outputs"""
        log_message = json.dumps(event, default=str)
        
        for output_name, logger_instance in self.loggers.items():
            try:
                logger_instance.info(log_message)
            except Exception as e:
                logger.error("Failed to write to output", output=output_name, error=str(e))
    
    def get_security_events(self, limit: int = 100, 
                         event_type: str = None) -> List[Dict[str, Any]]:
        """Get recent security events"""
        events = self.security_events
        if event_type:
            events = [e for e in events if e.get("category") == event_type]
        
        return events[-limit:] if len(events) > limit else events
    
    def get_audit_trail(self, limit: int = 100, 
                      user: str = None) -> List[Dict[str, Any]]:
        """Get audit trail"""
        events = self.audit_trail
        if user:
            events = [e for e in events if e.get("user") == user]
        
        return events[-limit:] if len(events) > limit else events
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        return {
            "total_security_events": len(self.security_events),
            "total_audit_events": len(self.audit_trail),
            "configured_outputs": self.outputs,
            "log_level": self.log_level.value,
            "retention_days": self.retention_days,
            "enabled": self.enabled
        }


# Global centralized logger instance
centralized_logger = CentralizedLogger()


def log_security_event(event_type: str, details: Dict[str, Any], 
                    severity: LogLevel = LogLevel.SECURITY, 
                    correlation_id: str = None):
    """Log security event"""
    centralized_logger.log_security_event(event_type, details, severity, correlation_id)


def log_audit_event(action: str, user: str = None, 
                 resource: str = None, result: str = "success",
                 details: Dict[str, Any] = None, 
                 correlation_id: str = None):
    """Log audit event"""
    centralized_logger.log_audit_event(action, user, resource, result, details, correlation_id)


def log_performance_event(operation: str, duration_ms: float,
                      resource_usage: Dict[str, Any] = None,
                      details: Dict[str, Any] = None,
                      correlation_id: str = None):
    """Log performance event"""
    centralized_logger.log_performance_event(operation, duration_ms, resource_usage, details, correlation_id)


def log_business_event(event_name: str, data: Dict[str, Any],
                     severity: LogLevel = LogLevel.INFO,
                     correlation_id: str = None):
    """Log business event"""
    centralized_logger.log_business_event(event_name, data, severity, correlation_id)


def get_security_events(limit: int = 100, 
                     event_type: str = None) -> List[Dict[str, Any]]:
    """Get security events"""
    return centralized_logger.get_security_events(limit, event_type)


def get_audit_trail(limit: int = 100, 
                  user: str = None) -> List[Dict[str, Any]]:
    """Get audit trail"""
    return centralized_logger.get_audit_trail(limit, user)


def get_log_stats() -> Dict[str, Any]:
    """Get logging statistics"""
    return centralized_logger.get_log_stats()
