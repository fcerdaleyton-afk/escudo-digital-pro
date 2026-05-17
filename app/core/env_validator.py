#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Environment Validator
Comprehensive environment variable validation and secure defaults
"""

import os
import sys
import secrets
import hashlib
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """Validation status enumeration"""
    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"
    WEAK = "weak"
    INSECURE = "insecure"


@dataclass
class ValidationResult:
    """Validation result data structure"""
    variable: str
    status: ValidationStatus
    value: Optional[str]
    description: str
    recommendation: Optional[str] = None
    is_critical: bool = False


class EnvironmentValidator:
    """Comprehensive environment variable validator"""
    
    def __init__(self):
        """Initialize environment validator"""
        self.validation_results: Dict[str, ValidationResult] = {}
        self.secure_defaults = self._generate_secure_defaults()
        self.critical_variables = self._get_critical_variables()
        self.validation_rules = self._get_validation_rules()
        
    def _generate_secure_defaults(self) -> Dict[str, str]:
        """Generate secure default values"""
        return {
            'DB_PASSWORD': self._generate_secure_password(32),
            'JWT_SECRET': self._generate_secure_token(64),
            'REDIS_PASSWORD': self._generate_secure_password(24),
            'GRAFANA_PASSWORD': self._generate_secure_password(16),
            'SECRET_KEY': self._generate_secure_token(64),
            'ENCRYPTION_KEY': self._generate_secure_token(64),
            'API_RATE_LIMIT': '100',
            'SESSION_TIMEOUT': '3600',
            'MAX_LOGIN_ATTEMPTS': '5',
            'LOG_LEVEL': 'INFO',
            'ENVIRONMENT': 'production',
            'SECURITY_LEVEL': 'high',
            'DEBUG_ENABLED': 'false',
            'CORS_ORIGINS': 'http://localhost:3000,http://localhost:8080',
            'ALLOWED_HOSTS': 'localhost,127.0.0.1',
            'REDIS_URL': 'redis://localhost:6379/0',
            'DATABASE_URL': 'postgresql://maryuser:DB_PASSWORD_PLACEHOLDER@localhost:5432/maryv5',
            'SMTP_PORT': '587',
            'SMTP_USE_TLS': 'true',
            'SMTP_USE_SSL': 'false',
            'PROMETHEUS_ENABLED': 'true',
            'GRAFANA_ENABLED': 'true',
            'HOST_GUARDIAN_ENABLED': 'true',
            'THREAT_ENGINE_ENABLED': 'true',
            'TELEMETRY_ENABLED': 'true',
            'WEBSOCKET_ENABLED': 'true',
            'ALERT_EMAIL_ENABLED': 'true',
            'BACKUP_ENABLED': 'true',
            'AUTO_BACKUP_INTERVAL': '86400',
            'MAX_BACKUP_RETENTION': '30',
            'HEALTH_CHECK_INTERVAL': '30',
            'METRICS_RETENTION_DAYS': '30',
            'AUDIT_LOG_RETENTION_DAYS': '90',
            'MAX_CONCURRENT_SESSIONS': '100',
            'SESSION_COOKIE_SECURE': 'true',
            'SESSION_COOKIE_HTTPONLY': 'true',
            'SESSION_COOKIE_SAMESITE': 'strict',
            'CSRF_PROTECTION': 'true',
            'XSS_PROTECTION': 'true',
            'CONTENT_TYPE_NOSNIFF': 'true',
            'FRAME_OPTIONS_DENY': 'true',
            'HSTS_MAX_AGE': '31536000',
            'PERMISSIONS_POLICY': 'geolocation=(), microphone=(), camera=()'
        }
    
    def _generate_secure_password(self, length: int = 32) -> str:
        """Generate secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _generate_secure_token(self, length: int = 64) -> str:
        """Generate secure token"""
        return secrets.token_urlsafe(length)
    
    def _get_critical_variables(self) -> List[str]:
        """Get list of critical variables"""
        return [
            'DB_PASSWORD',
            'JWT_SECRET',
            'REDIS_PASSWORD',
            'GRAFANA_PASSWORD',
            'SECRET_KEY',
            'ENCRYPTION_KEY',
            'SMTP_HOST',
            'SMTP_PORT',
            'SMTP_USER',
            'SMTP_PASSWORD',
            'ALERT_EMAIL'
        ]
    
    def _get_validation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Get validation rules for environment variables"""
        return {
            'DB_PASSWORD': {
                'min_length': 16,
                'required': True,
                'complexity': True,
                'description': 'Database password'
            },
            'JWT_SECRET': {
                'min_length': 32,
                'required': True,
                'description': 'JWT signing secret'
            },
            'REDIS_PASSWORD': {
                'min_length': 12,
                'required': True,
                'description': 'Redis password'
            },
            'GRAFANA_PASSWORD': {
                'min_length': 8,
                'required': True,
                'description': 'Grafana admin password'
            },
            'SECRET_KEY': {
                'min_length': 32,
                'required': True,
                'description': 'Application secret key'
            },
            'ENCRYPTION_KEY': {
                'min_length': 32,
                'required': True,
                'description': 'Data encryption key'
            },
            'SMTP_HOST': {
                'required': True,
                'format': 'hostname',
                'description': 'SMTP server hostname'
            },
            'SMTP_PORT': {
                'required': True,
                'format': 'port',
                'description': 'SMTP server port'
            },
            'SMTP_USER': {
                'required': True,
                'description': 'SMTP username'
            },
            'SMTP_PASSWORD': {
                'required': True,
                'min_length': 8,
                'description': 'SMTP password'
            },
            'ALERT_EMAIL': {
                'required': True,
                'format': 'email',
                'description': 'Alert notification email'
            },
            'ENVIRONMENT': {
                'required': True,
                'values': ['development', 'staging', 'production'],
                'description': 'Application environment'
            },
            'LOG_LEVEL': {
                'values': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                'description': 'Logging level'
            },
            'SECURITY_LEVEL': {
                'values': ['low', 'medium', 'high'],
                'description': 'Security level'
            },
            'DEBUG_ENABLED': {
                'values': ['true', 'false'],
                'description': 'Debug mode flag'
            }
        }
    
    def validate_all(self) -> Dict[str, ValidationResult]:
        """Validate all environment variables"""
        self.validation_results = {}
        
        # Validate all known variables
        for variable, rules in self.validation_rules.items():
            result = self._validate_variable(variable, rules)
            self.validation_results[variable] = result
        
        # Check for unknown variables
        known_variables = set(self.validation_rules.keys())
        environment_variables = set(os.environ.keys())
        unknown_variables = environment_variables - known_variables
        
        for var in unknown_variables:
            if var.startswith(('MARY_', 'DB_', 'JWT_', 'REDIS_', 'GRAFANA_', 'SMTP_')):
                logger.warning(f"Unknown environment variable detected: {var}")
        
        return self.validation_results
    
    def _validate_variable(self, variable: str, rules: Dict[str, Any]) -> ValidationResult:
        """Validate individual environment variable"""
        value = os.environ.get(variable)
        
        # Check if variable exists
        if not value:
            if rules.get('required', False):
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.MISSING,
                    value=None,
                    description=f"Required environment variable {variable} is missing",
                    recommendation=f"Set {variable}={self.secure_defaults.get(variable, 'REQUIRED')}",
                    is_critical=variable in self.critical_variables
                )
            else:
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.VALID,
                    value=None,
                    description=f"Optional environment variable {variable} not set"
                )
        
        # Validate format
        if 'format' in rules:
            format_result = self._validate_format(variable, value, rules['format'])
            if format_result:
                return format_result
        
        # Validate values
        if 'values' in rules:
            if value not in rules['values']:
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.INVALID,
                    value=value,
                    description=f"Invalid value for {variable}: {value}",
                    recommendation=f"Must be one of: {', '.join(rules['values'])}"
                )
        
        # Validate length
        if 'min_length' in rules:
            if len(value) < rules['min_length']:
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.WEAK,
                    value=value,
                    description=f"{variable} is too short (min: {rules['min_length']})",
                    recommendation=f"Use a longer value for {variable}"
                )
        
        # Validate complexity
        if rules.get('complexity', False):
            complexity_result = self._validate_complexity(variable, value)
            if complexity_result:
                return complexity_result
        
        # Valid
        return ValidationResult(
            variable=variable,
            status=ValidationStatus.VALID,
            value=value,
            description=f"{variable} is valid"
        )
    
    def _validate_format(self, variable: str, value: str, format_type: str) -> Optional[ValidationResult]:
        """Validate variable format"""
        import re
        
        if format_type == 'email':
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, value):
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.INVALID,
                    value=value,
                    description=f"Invalid email format for {variable}: {value}",
                    recommendation="Use a valid email address"
                )
        
        elif format_type == 'port':
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    raise ValueError()
            except ValueError:
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.INVALID,
                    value=value,
                    description=f"Invalid port number for {variable}: {value}",
                    recommendation="Use a valid port number (1-65535)"
                )
        
        elif format_type == 'hostname':
            hostname_pattern = r'^[a-zA-Z0-9.-]+$'
            if not re.match(hostname_pattern, value):
                return ValidationResult(
                    variable=variable,
                    status=ValidationStatus.INVALID,
                    value=value,
                    description=f"Invalid hostname format for {variable}: {value}",
                    recommendation="Use a valid hostname"
                )
        
        return None
    
    def _validate_complexity(self, variable: str, value: str) -> Optional[ValidationResult]:
        """Validate password complexity"""
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in value)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_score < 3:
            return ValidationResult(
                variable=variable,
                status=ValidationStatus.WEAK,
                value=value,
                description=f"{variable} lacks complexity (score: {complexity_score}/4)",
                recommendation="Include uppercase, lowercase, digits, and special characters"
            )
        
        return None
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get validation summary"""
        if not self.validation_results:
            self.validate_all()
        
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results.values() if r.status == ValidationStatus.VALID)
        invalid = sum(1 for r in self.validation_results.values() if r.status == ValidationStatus.INVALID)
        missing = sum(1 for r in self.validation_results.values() if r.status == ValidationStatus.MISSING)
        weak = sum(1 for r in self.validation_results.values() if r.status == ValidationStatus.WEAK)
        critical = sum(1 for r in self.validation_results.values() if r.is_critical and r.status != ValidationStatus.VALID)
        
        return {
            'total_variables': total,
            'valid': valid,
            'invalid': invalid,
            'missing': missing,
            'weak': weak,
            'critical_issues': critical,
            'overall_status': 'PASS' if critical == 0 and invalid == 0 else 'FAIL',
            'results': {var: result.__dict__ for var, result in self.validation_results.items()}
        }
    
    def generate_env_file(self, filename: str = 'production.env.example') -> str:
        """Generate production environment file example"""
        try:
            env_content = []
            env_content.append("# ============================================")
            env_content.append("# MARY V5 SHIELD CORE - Production Environment")
            env_content.append("# Generated secure defaults - DO NOT use in production")
            env_content.append("# Replace placeholder values with actual secure values")
            env_content.append("# ============================================")
            env_content.append("")
            
            # Add critical variables first
            env_content.append("# ============================================")
            env_content.append("# CRITICAL SECURITY VARIABLES")
            env_content.append("# ============================================")
            env_content.append("")
            
            for var in self.critical_variables:
                default_value = self.secure_defaults.get(var, 'REQUIRED')
                rules = self.validation_rules.get(var, {})
                description = rules.get('description', '')
                
                env_content.append(f"# {description}")
                env_content.append(f"{var}={default_value}")
                env_content.append("")
            
            # Add other variables
            env_content.append("# ============================================")
            env_content.append("# CONFIGURATION VARIABLES")
            env_content.append("# ============================================")
            env_content.append("")
            
            for var, default_value in self.secure_defaults.items():
                if var not in self.critical_variables:
                    rules = self.validation_rules.get(var, {})
                    description = rules.get('description', '')
                    
                    env_content.append(f"# {description}")
                    env_content.append(f"{var}={default_value}")
                    env_content.append("")
            
            # Write to file
            with open(filename, 'w') as f:
                f.write('\n'.join(env_content))
            
            return f"Generated {filename} with secure defaults"
            
        except Exception as e:
            logger.error(f"Error generating env file: {e}")
            return f"Error generating env file: {e}"
    
    def fail_on_critical(self) -> bool:
        """Check if there are critical validation failures"""
        if not self.validation_results:
            self.validate_all()
        
        critical_failures = [
            result for result in self.validation_results.values()
            if result.is_critical and result.status != ValidationStatus.VALID
        ]
        
        if critical_failures:
            logger.error("CRITICAL: Environment validation failed")
            for failure in critical_failures:
                logger.error(f"  {failure.variable}: {failure.description}")
                if failure.recommendation:
                    logger.error(f"    Recommendation: {failure.recommendation}")
            
            return True
        
        return False
    
    def apply_secure_defaults(self) -> Dict[str, str]:
        """Apply secure defaults to environment"""
        applied = {}
        
        for var, default_value in self.secure_defaults.items():
            if var not in os.environ:
                os.environ[var] = default_value
                applied[var] = default_value
                logger.info(f"Applied secure default for {var}")
        
        return applied


# Global environment validator instance
env_validator = EnvironmentValidator()


# API functions
def validate_environment() -> Dict[str, Any]:
    """Validate all environment variables"""
    try:
        results = env_validator.validate_all()
        summary = env_validator.get_validation_summary()
        
        if summary['critical_issues'] > 0:
            logger.error(f"Environment validation FAILED: {summary['critical_issues']} critical issues")
        else:
            logger.info("Environment validation PASSED")
        
        return summary
        
    except Exception as e:
        logger.error(f"Error validating environment: {e}")
        return {'error': str(e), 'overall_status': 'ERROR'}


def generate_production_env() -> str:
    """Generate production environment file"""
    try:
        return env_validator.generate_env_file('production.env.example')
    except Exception as e:
        logger.error(f"Error generating production env: {e}")
        return f"Error generating production env: {e}"


def apply_secure_defaults() -> Dict[str, str]:
    """Apply secure defaults to environment"""
    try:
        return env_validator.apply_secure_defaults()
    except Exception as e:
        logger.error(f"Error applying secure defaults: {e}")
        return {}


def fail_on_critical_issues() -> bool:
    """Fail startup if critical issues exist"""
    try:
        return env_validator.fail_on_critical()
    except Exception as e:
        logger.error(f"Error checking critical issues: {e}")
        return True


def get_validation_results() -> Dict[str, Any]:
    """Get validation results"""
    try:
        return env_validator.get_validation_summary()
    except Exception as e:
        logger.error(f"Error getting validation results: {e}")
        return {'error': str(e)}


# Initialize environment validation
def initialize_environment_validation() -> str:
    """Initialize environment validation"""
    try:
        logger.info("Initializing environment validation")
        
        # Validate environment
        validation_results = validate_environment()
        
        # Fail on critical issues
        if fail_on_critical_issues():
            raise RuntimeError("Critical environment validation failures detected")
        
        # Apply secure defaults for missing non-critical variables
        applied_defaults = apply_secure_defaults()
        if applied_defaults:
            logger.info(f"Applied {len(applied_defaults)} secure defaults")
        
        logger.info("Environment validation initialized successfully")
        return "Environment validation initialized successfully"
        
    except Exception as e:
        logger.error(f"Error initializing environment validation: {e}")
        return f"Error initializing environment validation: {e}"
