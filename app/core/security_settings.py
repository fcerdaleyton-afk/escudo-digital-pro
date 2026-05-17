"""
MARY V5 SHIELD CORE - Global Security Configuration
Centralized security configuration with validation and fail-safe defaults
"""

import os
import json
import secrets
import hashlib
from typing import Dict, List, Optional, Any, Union, Type, get_type_hints
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging
from pydantic import BaseModel, validator, Field, ValidationError
import asyncio
from datetime import datetime, timedelta

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger


class SecurityLevel(Enum):
    """Security levels for configuration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(Enum):
    """Environment types"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class ConfigurationError(Exception):
    """Configuration validation error"""
    pass


@dataclass
class SecurityConfigValidation:
    """Security configuration validation rules"""
    field: str
    required: bool = False
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    allowed_values: Optional[List[str]] = None
    pattern: Optional[str] = None
    secret: bool = False
    validation_function: Optional[callable] = None


class SecuritySettings(BaseModel):
    """
    Centralized security settings with validation and secure defaults
    """
    
    # Core Configuration
    environment: Environment = Field(default=Environment.PRODUCTION)
    security_level: SecurityLevel = Field(default=SecurityLevel.HIGH)
    debug_enabled: bool = Field(default=False)
    
    # Security Engine Configuration
    security_engine_enabled: bool = Field(default=True)
    security_engine_workers: int = Field(default=4, ge=1, le=20)
    security_engine_queue_size: int = Field(default=10000, ge=1000, le=100000)
    security_engine_timeout: float = Field(default=30.0, ge=1.0, le=300.0)
    
    # Threat Detection Configuration
    threat_detection_enabled: bool = Field(default=True)
    threat_detection_interval: int = Field(default=60, ge=10, le=300)
    threat_retention_days: int = Field(default=90, ge=7, le=365)
    threat_auto_mitigation: bool = Field(default=True)
    
    # Rate Limiting Configuration
    rate_limiting_enabled: bool = Field(default=True)
    global_rps: int = Field(default=100, ge=10, le=10000)
    ip_rps: int = Field(default=10, ge=1, le=1000)
    burst_allowance: int = Field(default=5, ge=1, le=50)
    rate_limit_window: int = Field(default=60, ge=10, le=3600)
    
    # DDoS Protection Configuration
    ddos_protection_enabled: bool = Field(default=True)
    ddos_threshold: int = Field(default=1000, ge=100, le=100000)
    ddos_block_duration: int = Field(default=300, ge=60, le=3600)
    ddos_whitelist_enabled: bool = Field(default=True)
    
    # API Hardening Configuration
    api_hardening_enabled: bool = Field(default=True)
    max_request_size_mb: int = Field(default=10, ge=1, le=100)
    max_header_size_kb: int = Field(default=8, ge=1, le=64)
    max_url_length: int = Field(default=2048, ge=256, le=8192)
    request_timeout: float = Field(default=30.0, ge=1.0, le=300.0)
    
    # Security Headers Configuration
    security_headers_enabled: bool = Field(default=True)
    hsts_enabled: bool = Field(default=True)
    hsts_max_age: int = Field(default=31536000, ge=86400, le=31536000)
    hsts_include_subdomains: bool = Field(default=True)
    hsts_preload: bool = Field(default=False)
    csp_enabled: bool = Field(default=True)
    csp_report_only: bool = Field(default=False)
    
    # Authentication Configuration
    authentication_enabled: bool = Field(default=True)
    jwt_secret: str = Field(default="")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiration_minutes: int = Field(default=15, ge=5, le=1440)
    jwt_refresh_expiration_days: int = Field(default=7, ge=1, le=30)
    zero_trust_enabled: bool = Field(default=True)
    
    # Database Security Configuration
    database_security_enabled: bool = Field(default=True)
    database_encryption_enabled: bool = Field(default=True)
    database_audit_enabled: bool = Field(default=True)
    database_connection_timeout: float = Field(default=30.0, ge=5.0, le=120.0)
    
    # Cache Configuration
    cache_enabled: bool = Field(default=True)
    cache_type: str = Field(default="redis", regex="^(redis|memory)$")
    cache_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    cache_max_size: int = Field(default=10000, ge=1000, le=100000)
    
    # Logging Configuration
    structured_logging_enabled: bool = Field(default=True)
    log_level: str = Field(default="INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_retention_days: int = Field(default=90, ge=7, le=365)
    log_to_file: bool = Field(default=True)
    log_to_console: bool = Field(default=True)
    
    # Monitoring Configuration
    monitoring_enabled: bool = Field(default=True)
    metrics_enabled: bool = Field(default=True)
    prometheus_enabled: bool = Field(default=True)
    health_check_enabled: bool = Field(default=True)
    
    # WebSocket Configuration
    websocket_enabled: bool = Field(default=True)
    websocket_port: int = Field(default=8765, ge=1024, le=65535)
    websocket_max_connections: int = Field(default=1000, ge=10, le=10000)
    
    # Threat Intelligence Configuration
    threat_intel_enabled: bool = Field(default=True)
    threat_intel_offline_mode: bool = Field(default=False)
    threat_intel_update_interval: int = Field(default=3600, ge=300, le=86400)
    
    # Windows Defender Configuration
    windows_defender_enabled: bool = Field(default=True)
    windows_defender_interval: int = Field(default=300, ge=60, le=3600)
    
    # Performance Configuration
    performance_optimization_enabled: bool = Field(default=True)
    async_workers: int = Field(default=10, ge=1, le=50)
    memory_optimization_enabled: bool = Field(default=True)
    gc_threshold: float = Field(default=0.8, ge=0.5, le=0.95)
    
    # Circuit Breaker Configuration
    circuit_breaker_enabled: bool = Field(default=True)
    circuit_breaker_failure_threshold: int = Field(default=5, ge=3, le=20)
    circuit_breaker_timeout: float = Field(default=60.0, ge=10.0, le=300.0)
    circuit_breaker_recovery_timeout: float = Field(default=30.0, ge=10.0, le=120.0)
    
    @validator('jwt_secret')
    def validate_jwt_secret(cls, v, values):
        if values.get('authentication_enabled') and not v:
            raise ValueError('JWT secret is required when authentication is enabled')
        if len(v) < 32:
            raise ValueError('JWT secret must be at least 32 characters long')
        return v
    
    @validator('environment')
    def validate_environment(cls, v):
        if v == Environment.PRODUCTION:
            # Production requires higher security
            pass
        return v
    
    @validator('security_level')
    def validate_security_level(cls, v, values):
        env = values.get('environment', Environment.PRODUCTION)
        if env == Environment.PRODUCTION and v not in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            raise ValueError('Production environment requires HIGH or CRITICAL security level')
        return v
    
    @validator('debug_enabled')
    def validate_debug_enabled(cls, v, values):
        env = values.get('environment', Environment.PRODUCTION)
        if env == Environment.PRODUCTION and v:
            raise ValueError('Debug mode cannot be enabled in production')
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


class SecurityConfigManager:
    """
    Centralized security configuration manager with validation and fail-safe defaults
    """
    
    def __init__(self):
        self.enabled = os.getenv("SECURITY_CONFIG_ENABLED", "true").lower() == "true"
        
        # Configuration cache
        self._config: Optional[SecuritySettings] = None
        self._config_hash: Optional[str] = None
        self._last_validation: Optional[datetime] = None
        
        # Configuration validation rules
        self.validation_rules = self._load_validation_rules()
        
        # Secure defaults
        self.secure_defaults = self._load_secure_defaults()
        
        # Configuration file paths
        self.config_files = [
            "/app/config/security.json",
            "/app/config/security.yaml",
            os.path.expanduser("~/.mary-v5/security.json"),
            "security.json"
        ]
        
        # Logger
        self.logger = get_structured_logger("security_config")
        
        self.logger.info("Security configuration manager initialized", enabled=self.enabled)
    
    def _load_validation_rules(self) -> Dict[str, List[SecurityConfigValidation]]:
        """Load configuration validation rules"""
        return {
            "jwt_secret": [
                SecurityConfigValidation(
                    field="jwt_secret",
                    required=True,
                    secret=True,
                    validation_function=lambda x: len(x) >= 32
                )
            ],
            "security_level": [
                SecurityConfigValidation(
                    field="security_level",
                    allowed_values=["low", "medium", "high", "critical"]
                )
            ],
            "environment": [
                SecurityConfigValidation(
                    field="environment",
                    allowed_values=["development", "testing", "staging", "production"]
                )
            ],
            "security_engine_workers": [
                SecurityConfigValidation(
                    field="security_engine_workers",
                    min_value=1,
                    max_value=20
                )
            ],
            "global_rps": [
                SecurityConfigValidation(
                    field="global_rps",
                    min_value=10,
                    max_value=10000
                )
            ],
            "max_request_size_mb": [
                SecurityConfigValidation(
                    field="max_request_size_mb",
                    min_value=1,
                    max_value=100
                )
            ],
            "jwt_expiration_minutes": [
                SecurityConfigValidation(
                    field="jwt_expiration_minutes",
                    min_value=5,
                    max_value=1440
                )
            ]
        }
    
    def _load_secure_defaults(self) -> Dict[str, Any]:
        """Load secure default values"""
        return {
            "environment": "production",
            "security_level": "high",
            "debug_enabled": False,
            "security_engine_enabled": True,
            "security_engine_workers": 4,
            "threat_detection_enabled": True,
            "rate_limiting_enabled": True,
            "ddos_protection_enabled": True,
            "api_hardening_enabled": True,
            "security_headers_enabled": True,
            "authentication_enabled": True,
            "database_security_enabled": True,
            "cache_enabled": True,
            "structured_logging_enabled": True,
            "monitoring_enabled": True,
            "circuit_breaker_enabled": True,
            "performance_optimization_enabled": True
        }
    
    async def load_configuration(self) -> SecuritySettings:
        """Load and validate security configuration"""
        if not self.enabled:
            return SecuritySettings(**self.secure_defaults)
        
        try:
            # Load configuration from environment
            config_data = await self._load_from_environment()
            
            # Override with file configuration if available
            file_config = await self._load_from_files()
            if file_config:
                config_data.update(file_config)
            
            # Apply secure defaults for missing values
            for key, default_value in self.secure_defaults.items():
                if key not in config_data:
                    config_data[key] = default_value
            
            # Create configuration object
            config = SecuritySettings(**config_data)
            
            # Validate configuration
            await self._validate_configuration(config)
            
            # Cache configuration
            self._config = config
            self._config_hash = self._calculate_config_hash(config)
            self._last_validation = datetime.utcnow()
            
            self.logger.info("Security configuration loaded and validated", 
                           environment=config.environment,
                           security_level=config.security_level.value)
            
            return config
            
        except Exception as e:
            self.logger.error("Failed to load security configuration", error=str(e))
            self.logger.warning("Falling back to secure defaults")
            return SecuritySettings(**self.secure_defaults)
    
    async def _load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        config = {}
        
        # Map environment variables to configuration keys
        env_mappings = {
            # Core Configuration
            "ENVIRONMENT": "environment",
            "SECURITY_LEVEL": "security_level",
            "DEBUG_ENABLED": "debug_enabled",
            
            # Security Engine
            "SECURITY_ENGINE_ENABLED": "security_engine_enabled",
            "SECURITY_ENGINE_WORKERS": "security_engine_workers",
            "SECURITY_ENGINE_QUEUE_SIZE": "security_engine_queue_size",
            "SECURITY_ENGINE_TIMEOUT": "security_engine_timeout",
            
            # Threat Detection
            "THREAT_DETECTION_ENABLED": "threat_detection_enabled",
            "THREAT_DETECTION_INTERVAL": "threat_detection_interval",
            "THREAT_RETENTION_DAYS": "threat_retention_days",
            "THREAT_AUTO_MITIGATION": "threat_auto_mitigation",
            
            # Rate Limiting
            "RATE_LIMITING_ENABLED": "rate_limiting_enabled",
            "GLOBAL_RPS": "global_rps",
            "IP_RPS": "ip_rps",
            "BURST_ALLOWANCE": "burst_allowance",
            "RATE_LIMIT_WINDOW": "rate_limit_window",
            
            # DDoS Protection
            "DDOS_PROTECTION_ENABLED": "ddos_protection_enabled",
            "DDOS_THRESHOLD": "ddos_threshold",
            "DDOS_BLOCK_DURATION": "ddos_block_duration",
            "DDOS_WHITELIST_ENABLED": "ddos_whitelist_enabled",
            
            # API Hardening
            "API_HARDENING_ENABLED": "api_hardening_enabled",
            "MAX_REQUEST_SIZE_MB": "max_request_size_mb",
            "MAX_HEADER_SIZE_KB": "max_header_size_kb",
            "MAX_URL_LENGTH": "max_url_length",
            "REQUEST_TIMEOUT": "request_timeout",
            
            # Security Headers
            "SECURITY_HEADERS_ENABLED": "security_headers_enabled",
            "HSTS_ENABLED": "hsts_enabled",
            "HSTS_MAX_AGE": "hsts_max_age",
            "HSTS_INCLUDE_SUBDOMAINS": "hsts_include_subdomains",
            "HSTS_PRELOAD": "hsts_preload",
            "CSP_ENABLED": "csp_enabled",
            "CSP_REPORT_ONLY": "csp_report_only",
            
            # Authentication
            "AUTHENTICATION_ENABLED": "authentication_enabled",
            "JWT_SECRET": "jwt_secret",
            "JWT_ALGORITHM": "jwt_algorithm",
            "JWT_EXPIRATION_MINUTES": "jwt_expiration_minutes",
            "JWT_REFRESH_EXPIRATION_DAYS": "jwt_refresh_expiration_days",
            "ZERO_TRUST_ENABLED": "zero_trust_enabled",
            
            # Database Security
            "DATABASE_SECURITY_ENABLED": "database_security_enabled",
            "DATABASE_ENCRYPTION_ENABLED": "database_encryption_enabled",
            "DATABASE_AUDIT_ENABLED": "database_audit_enabled",
            "DATABASE_CONNECTION_TIMEOUT": "database_connection_timeout",
            
            # Cache
            "CACHE_ENABLED": "cache_enabled",
            "CACHE_TYPE": "cache_type",
            "CACHE_TTL_SECONDS": "cache_ttl_seconds",
            "CACHE_MAX_SIZE": "cache_max_size",
            
            # Logging
            "STRUCTURED_LOGGING_ENABLED": "structured_logging_enabled",
            "LOG_LEVEL": "log_level",
            "LOG_RETENTION_DAYS": "log_retention_days",
            "LOG_TO_FILE": "log_to_file",
            "LOG_TO_CONSOLE": "log_to_console",
            
            # Monitoring
            "MONITORING_ENABLED": "monitoring_enabled",
            "METRICS_ENABLED": "metrics_enabled",
            "PROMETHEUS_ENABLED": "prometheus_enabled",
            "HEALTH_CHECK_ENABLED": "health_check_enabled",
            
            # WebSocket
            "WEBSOCKET_ENABLED": "websocket_enabled",
            "WEBSOCKET_PORT": "websocket_port",
            "WEBSOCKET_MAX_CONNECTIONS": "websocket_max_connections",
            
            # Threat Intelligence
            "THREAT_INTEL_ENABLED": "threat_intel_enabled",
            "THREAT_INTEL_OFFLINE_MODE": "threat_intel_offline_mode",
            "THREAT_INTEL_UPDATE_INTERVAL": "threat_intel_update_interval",
            
            # Windows Defender
            "WINDOWS_DEFENDER_ENABLED": "windows_defender_enabled",
            "WINDOWS_DEFENDER_INTERVAL": "windows_defender_interval",
            
            # Performance
            "PERFORMANCE_OPTIMIZATION_ENABLED": "performance_optimization_enabled",
            "ASYNC_WORKERS": "async_workers",
            "MEMORY_OPTIMIZATION_ENABLED": "memory_optimization_enabled",
            "GC_THRESHOLD": "gc_threshold",
            
            # Circuit Breaker
            "CIRCUIT_BREAKER_ENABLED": "circuit_breaker_enabled",
            "CIRCUIT_BREAKER_FAILURE_THRESHOLD": "circuit_breaker_failure_threshold",
            "CIRCUIT_BREAKER_TIMEOUT": "circuit_breaker_timeout",
            "CIRCUIT_BREAKER_RECOVERY_TIMEOUT": "circuit_breaker_recovery_timeout"
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                converted_value = self._convert_env_value(config_key, value)
                if converted_value is not None:
                    config[config_key] = converted_value
        
        return config
    
    def _convert_env_value(self, key: str, value: str) -> Any:
        """Convert environment variable value to appropriate type"""
        # Get type hints from SecuritySettings
        hints = get_type_hints(SecuritySettings)
        
        if key not in hints:
            return value
        
        target_type = hints[key]
        
        # Handle special cases
        if target_type == bool:
            return value.lower() in ("true", "1", "yes", "on")
        elif target_type == int:
            try:
                return int(value)
            except ValueError:
                return None
        elif target_type == float:
            try:
                return float(value)
            except ValueError:
                return None
        elif target_type == Environment:
            try:
                return Environment(value.lower())
            except ValueError:
                return Environment.PRODUCTION
        elif target_type == SecurityLevel:
            try:
                return SecurityLevel(value.lower())
            except ValueError:
                return SecurityLevel.HIGH
        
        return value
    
    async def _load_from_files(self) -> Optional[Dict[str, Any]]:
        """Load configuration from files"""
        for config_file in self.config_files:
            try:
                if os.path.exists(config_file):
                    config_data = await self._load_config_file(config_file)
                    if config_data:
                        self.logger.info(f"Loaded configuration from {config_file}")
                        return config_data
            except Exception as e:
                self.logger.warning(f"Failed to load config file {config_file}: {e}")
        
        return None
    
    async def _load_config_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Load configuration from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.json'):
                    return json.load(f)
                elif file_path.endswith(('.yaml', '.yml')):
                    import yaml
                    return yaml.safe_load(f)
                else:
                    self.logger.warning(f"Unsupported config file format: {file_path}")
                    return None
        except Exception as e:
            self.logger.error(f"Error loading config file {file_path}: {e}")
            return None
    
    async def _validate_configuration(self, config: SecuritySettings):
        """Validate configuration against security rules"""
        validation_errors = []
        
        # Validate each field according to rules
        for field_name, rules in self.validation_rules.items():
            field_value = getattr(config, field_name, None)
            
            for rule in rules:
                try:
                    # Check required fields
                    if rule.required and field_value is None:
                        validation_errors.append(f"{rule.field} is required")
                        continue
                    
                    # Check value range
                    if field_value is not None:
                        if rule.min_value is not None and field_value < rule.min_value:
                            validation_errors.append(
                                f"{rule.field} must be >= {rule.min_value}, got {field_value}"
                            )
                        
                        if rule.max_value is not None and field_value > rule.max_value:
                            validation_errors.append(
                                f"{rule.field} must be <= {rule.max_value}, got {field_value}"
                            )
                        
                        # Check allowed values
                        if rule.allowed_values and field_value not in rule.allowed_values:
                            if hasattr(field_value, 'value'):
                                field_value = field_value.value
                            if field_value not in rule.allowed_values:
                                validation_errors.append(
                                    f"{rule.field} must be one of {rule.allowed_values}, got {field_value}"
                                )
                        
                        # Check pattern
                        if rule.pattern and isinstance(field_value, str):
                            import re
                            if not re.match(rule.pattern, field_value):
                                validation_errors.append(
                                    f"{rule.field} does not match required pattern"
                                )
                        
                        # Custom validation function
                        if rule.validation_function and not rule.validation_function(field_value):
                            validation_errors.append(f"{rule.field} failed validation")
                    
                except Exception as e:
                    validation_errors.append(f"Error validating {rule.field}: {e}")
        
        # Environment-specific validations
        if config.environment == Environment.PRODUCTION:
            if config.debug_enabled:
                validation_errors.append("Debug mode cannot be enabled in production")
            
            if config.security_level not in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                validation_errors.append("Production requires HIGH or CRITICAL security level")
            
            if not config.jwt_secret:
                validation_errors.append("JWT secret is required in production")
            elif len(config.jwt_secret) < 32:
                validation_errors.append("JWT secret must be at least 32 characters long")
        
        # Security-critical validations
        if config.authentication_enabled and not config.jwt_secret:
            validation_errors.append("JWT secret is required when authentication is enabled")
        
        if config.rate_limiting_enabled and config.global_rps < 10:
            validation_errors.append("Global RPS must be at least 10 when rate limiting is enabled")
        
        if config.api_hardening_enabled and config.max_request_size_mb > 100:
            validation_errors.append("Max request size should not exceed 100MB")
        
        if validation_errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in validation_errors)
            self.logger.error(error_msg)
            raise ConfigurationError(error_msg)
        
        self.logger.info("Configuration validation passed")
    
    def _calculate_config_hash(self, config: SecuritySettings) -> str:
        """Calculate configuration hash for change detection"""
        config_dict = config.dict()
        # Remove sensitive fields from hash calculation
        sensitive_fields = ['jwt_secret']
        for field in sensitive_fields:
            config_dict.pop(field, None)
        
        config_str = json.dumps(config_dict, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    async def get_configuration(self) -> SecuritySettings:
        """Get current configuration (load if not cached)"""
        if not self.enabled:
            return SecuritySettings(**self.secure_defaults)
        
        if self._config is None:
            return await self.load_configuration()
        
        # Check if configuration has changed
        current_hash = self._calculate_config_hash(self._config)
        if current_hash != self._config_hash:
            return await self.load_configuration()
        
        return self._config
    
    async def reload_configuration(self) -> SecuritySettings:
        """Force reload configuration"""
        self._config = None
        self._config_hash = None
        return await self.load_configuration()
    
    def is_configuration_valid(self) -> bool:
        """Check if current configuration is valid"""
        return self._config is not None and self._last_validation is not None
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        if not self._config:
            return {"enabled": self.enabled}
        
        return {
            "enabled": self.enabled,
            "environment": self._config.environment.value,
            "security_level": self._config.security_level.value,
            "last_validation": self._last_validation.isoformat() if self._last_validation else None,
            "config_hash": self._config_hash,
            "components": {
                "security_engine": self._config.security_engine_enabled,
                "threat_detection": self._config.threat_detection_enabled,
                "rate_limiting": self._config.rate_limiting_enabled,
                "ddos_protection": self._config.ddos_protection_enabled,
                "api_hardening": self._config.api_hardening_enabled,
                "security_headers": self._config.security_headers_enabled,
                "authentication": self._config.authentication_enabled,
                "database_security": self._config.database_security_enabled,
                "monitoring": self._config.monitoring_enabled,
                "circuit_breaker": self._config.circuit_breaker_enabled
            }
        }


# Global security configuration manager
security_config_manager = SecurityConfigManager()


async def get_security_settings() -> SecuritySettings:
    """Get global security settings"""
    return await security_config_manager.get_configuration()


async def reload_security_settings() -> SecuritySettings:
    """Reload global security settings"""
    return await security_config_manager.reload_configuration()


def is_security_config_valid() -> bool:
    """Check if security configuration is valid"""
    return security_config_manager.is_configuration_valid()


def get_security_config_summary() -> Dict[str, Any]:
    """Get security configuration summary"""
    return security_config_manager.get_configuration_summary()
