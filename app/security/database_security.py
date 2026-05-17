"""
Database Security for Mary V5 Enterprise
Encrypted sensitive fields, SQL injection prevention, and audit logging
"""

import os
import json
import hashlib
import hmac
import asyncio
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class FieldEncryption:
    """Field-level encryption for sensitive data"""
    
    def __init__(self):
        self.enabled = os.getenv("FIELD_ENCRYPTION_ENABLED", "true").lower() == "true"
        
        # Encryption key management
        self.encryption_key = self._load_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key) if self.enabled else None
        
        # Sensitive field patterns
        self.sensitive_patterns = [
            r".*password.*", r".*secret.*", r".*token.*", r".*key.*",
            r".*credential.*", r".*auth.*", r".*private.*", r".*confidential.*"
        ]
        
        # Encrypted field registry
        self.encrypted_fields = set()
        
        logger.info("Field encryption initialized", enabled=self.enabled)
    
    def _load_encryption_key(self) -> bytes:
        """Load or generate encryption key"""
        key_file = os.getenv("ENCRYPTION_KEY_FILE", "/app/data/encryption.key")
        key_password = os.getenv("ENCRYPTION_KEY_PASSWORD", "default_password").encode()
        
        try:
            # Load existing key
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    encrypted_key = f.read()
                
                # Decrypt key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'salt_value',  # In production, use proper salt
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(key_password))
                
                return key
            
            # Generate new key
            key = Fernet.generate_key()
            
            # Save encrypted key
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            
            logger.info("Generated new encryption key")
            return key
            
        except Exception as e:
            logger.error("Failed to load encryption key", error=str(e))
            # Fallback to generated key
            return Fernet.generate_key()
    
    def encrypt_field(self, field_name: str, value: Any) -> Union[str, Any]:
        """Encrypt a field value"""
        if not self.enabled or not self.cipher_suite:
            return value
        
        # Check if field should be encrypted
        if not self._is_sensitive_field(field_name):
            return value
        
        try:
            # Convert to string if needed
            if not isinstance(value, str):
                value = str(value)
            
            # Encrypt
            encrypted_value = self.cipher_suite.encrypt(value.encode())
            
            # Store field in registry
            self.encrypted_fields.add(field_name)
            
            # Return as base64 string
            return base64.b64encode(encrypted_value).decode()
            
        except Exception as e:
            logger.error("Field encryption failed", field=field_name, error=str(e))
            return value
    
    def decrypt_field(self, field_name: str, encrypted_value: Union[str, Any]) -> Union[str, Any]:
        """Decrypt a field value"""
        if not self.enabled or not self.cipher_suite:
            return encrypted_value
        
        # Check if field is encrypted
        if field_name not in self.encrypted_fields:
            return encrypted_value
        
        try:
            # Handle non-string values
            if not isinstance(encrypted_value, str):
                return encrypted_value
            
            # Decode base64 and decrypt
            encrypted_bytes = base64.b64decode(encrypted_value)
            decrypted_value = self.cipher_suite.decrypt(encrypted_bytes)
            
            return decrypted_value.decode()
            
        except Exception as e:
            logger.error("Field decryption failed", field=field_name, error=str(e))
            return encrypted_value
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data"""
        field_name_lower = field_name.lower()
        
        for pattern in self.sensitive_patterns:
            if re.match(pattern, field_name_lower):
                return True
        
        return False
    
    def encrypt_dict_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in a dictionary"""
        if not self.enabled:
            return data
        
        encrypted_data = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursively encrypt nested dictionaries
                encrypted_data[key] = self.encrypt_dict_fields(value)
            elif isinstance(value, list):
                # Encrypt list items
                encrypted_data[key] = [
                    self.encrypt_field(key, item) if isinstance(item, (str, int, float)) else item
                    for item in value
                ]
            else:
                # Encrypt individual field
                encrypted_data[key] = self.encrypt_field(key, value)
        
        return encrypted_data
    
    def decrypt_dict_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields in a dictionary"""
        if not self.enabled:
            return data
        
        decrypted_data = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursively decrypt nested dictionaries
                decrypted_data[key] = self.decrypt_dict_fields(value)
            elif isinstance(value, list):
                # Decrypt list items
                decrypted_data[key] = [
                    self.decrypt_field(key, item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                # Decrypt individual field
                decrypted_data[key] = self.decrypt_field(key, value)
        
        return decrypted_data


class SQLInjectionDetector:
    """SQL injection detection and prevention"""
    
    def __init__(self):
        self.enabled = os.getenv("SQL_INJECTION_DETECTION_ENABLED", "true").lower() == "true"
        
        # SQL injection patterns
        self.injection_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(\b(or|and)\s+\d+\s*=\s*\d+)",
            r"(\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(;\s*(drop|delete|update|insert)\s)",
            r"(/\*.*\*/)",
            r"(--.*$)",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)",
            r"(\bopenrowset\b)",
            r"(\bopendatasource\b)"
        ]
        
        # Suspicious keywords
        self.suspicious_keywords = [
            "union", "select", "insert", "update", "delete", "drop",
            "create", "alter", "exec", "execute", "xp_cmdshell",
            "sp_executesql", "openrowset", "opendatasource"
        ]
        
        logger.info("SQL injection detector initialized", enabled=self.enabled)
    
    def detect_injection(self, input_value: str) -> Dict[str, Any]:
        """Detect SQL injection attempts"""
        if not self.enabled or not isinstance(input_value, str):
            return {"detected": False, "risk_score": 0, "patterns": []}
        
        input_lower = input_value.lower()
        detected_patterns = []
        risk_score = 0
        
        # Check for injection patterns
        for pattern in self.injection_patterns:
            matches = re.findall(pattern, input_lower, re.IGNORECASE)
            if matches:
                detected_patterns.extend(matches)
                risk_score += len(matches) * 10
        
        # Check for suspicious keywords
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in input_lower)
        if keyword_count > 0:
            risk_score += keyword_count * 5
        
        # Check for special characters
        special_chars = ["'", '"', ';', '--', '/*', '*/', '/*', '*/']
        special_char_count = sum(1 for char in special_chars if char in input_value)
        if special_char_count > 2:
            risk_score += special_char_count * 2
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        elif risk_score >= 10:
            risk_level = "low"
        else:
            risk_level = "safe"
        
        return {
            "detected": risk_score > 0,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "patterns": detected_patterns,
            "input_length": len(input_value)
        }
    
    def sanitize_input(self, input_value: str) -> str:
        """Sanitize input to prevent SQL injection"""
        if not isinstance(input_value, str):
            return input_value
        
        # Remove dangerous characters
        sanitized = re.sub(r"[;'\"]", "", input_value)
        
        # Remove SQL comments
        sanitized = re.sub(r"--.*$", "", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        
        return sanitized.strip()


class DatabaseAuditor:
    """Database operation auditing"""
    
    def __init__(self):
        self.enabled = os.getenv("DATABASE_AUDITING_ENABLED", "true").lower() == "true"
        
        # Audit log settings
        self.log_all_queries = os.getenv("LOG_ALL_QUERIES", "false").lower() == "true"
        self.log_sensitive_operations = os.getenv("LOG_SENSITIVE_OPERATIONS", "true").lower() == "true"
        
        # Sensitive operations
        self.sensitive_operations = {
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
            "ALTER", "GRANT", "REVOKE", "TRUNCATE"
        }
        
        # Audit history
        self.audit_log = []
        self.max_log_size = int(os.getenv("MAX_AUDIT_LOG_SIZE", "10000"))
        
        logger.info("Database auditor initialized", enabled=self.enabled)
    
    def log_database_operation(self, operation: str, table: str, user: str = None,
                            affected_rows: int = 0, query: str = None,
                            success: bool = True, error: str = None):
        """Log database operation"""
        if not self.enabled:
            return
        
        # Determine if operation should be logged
        should_log = (
            self.log_all_queries or
            (self.log_sensitive_operations and operation.upper() in self.sensitive_operations)
        )
        
        if not should_log:
            return
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation.upper(),
            "table": table,
            "user": user or "anonymous",
            "affected_rows": affected_rows,
            "query": query[:500] if query else None,  # Limit query length
            "success": success,
            "error": error,
            "risk_level": self._assess_operation_risk(operation, table, affected_rows)
        }
        
        # Add to audit log
        self.audit_log.append(audit_entry)
        
        # Trim log if needed
        if len(self.audit_log) > self.max_log_size:
            self.audit_log = self.audit_log[-self.max_log_size:]
        
        # Log to centralized logging
        log_audit_event(
            "database_operation",
            user=user,
            resource=f"{operation}:{table}",
            result="success" if success else "failed",
            details={
                "operation": operation,
                "table": table,
                "affected_rows": affected_rows,
                "risk_level": audit_entry["risk_level"]
            }
        )
        
        # Alert for suspicious operations
        if audit_entry["risk_level"] == "high":
            log_security_event(
                "suspicious_database_operation",
                {
                    "operation": operation,
                    "table": table,
                    "user": user,
                    "affected_rows": affected_rows,
                    "query": query
                }
            )
    
    def _assess_operation_risk(self, operation: str, table: str, affected_rows: int) -> str:
        """Assess risk level of database operation"""
        operation_upper = operation.upper()
        
        # High-risk operations
        if operation_upper in ["DROP", "TRUNCATE"]:
            return "high"
        
        # Medium-risk operations
        if operation_upper in ["DELETE", "UPDATE"] and affected_rows > 100:
            return "medium"
        
        # Sensitive tables
        sensitive_tables = ["users", "credentials", "secrets", "keys", "tokens"]
        if any(sensitive in table.lower() for sensitive in sensitive_tables):
            return "high"
        
        # Large operations
        if affected_rows > 1000:
            return "medium"
        
        return "low"
    
    def get_audit_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get audit summary for specified time period"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        recent_operations = [
            entry for entry in self.audit_log
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
        ]
        
        # Operation statistics
        operation_counts = {}
        risk_counts = {"low": 0, "medium": 0, "high": 0}
        failure_count = 0
        
        for entry in recent_operations:
            op = entry["operation"]
            operation_counts[op] = operation_counts.get(op, 0) + 1
            risk_counts[entry["risk_level"]] += 1
            
            if not entry["success"]:
                failure_count += 1
        
        return {
            "period_hours": hours,
            "total_operations": len(recent_operations),
            "operation_counts": operation_counts,
            "risk_distribution": risk_counts,
            "failure_count": failure_count,
            "success_rate": (len(recent_operations) - failure_count) / len(recent_operations) * 100 if recent_operations else 100
        }
    
    def get_recent_operations(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent database operations"""
        return self.audit_log[-limit:]


class DatabaseSecurityManager:
    """Main database security manager"""
    
    def __init__(self):
        self.enabled = os.getenv("DATABASE_SECURITY_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.field_encryption = FieldEncryption()
        self.injection_detector = SQLInjectionDetector()
        self.auditor = DatabaseAuditor()
        
        logger.info("Database security manager initialized", enabled=self.enabled)
    
    def secure_query_input(self, query: str, params: Dict[str, Any] = None, 
                         user: str = None) -> Tuple[str, Dict[str, Any]]:
        """Secure query input and detect injection attempts"""
        if not self.enabled:
            return query, params or {}
        
        # Detect SQL injection
        injection_result = self.injection_detector.detect_injection(query)
        
        if injection_result["detected"]:
            # Log injection attempt
            log_security_event(
                "sql_injection_attempt",
                {
                    "query": query[:200],  # Limit length
                    "risk_score": injection_result["risk_score"],
                    "patterns": injection_result["patterns"],
                    "user": user
                }
            )
            
            # Block high-risk attempts
            if injection_result["risk_level"] in ["high", "medium"]:
                raise SecurityError(f"SQL injection detected: {injection_result['risk_level']}")
            
            # Sanitize input for low-risk
            query = self.injection_detector.sanitize_input(query)
        
        # Encrypt sensitive parameters
        if params:
            params = self.field_encryption.encrypt_dict_fields(params)
        
        return query, params
    
    def secure_data_output(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Secure data output by decrypting sensitive fields"""
        if not self.enabled:
            return data
        
        return self.field_encryption.decrypt_dict_fields(data)
    
    def log_operation(self, operation: str, table: str, user: str = None,
                     affected_rows: int = 0, query: str = None,
                     success: bool = True, error: str = None):
        """Log database operation"""
        if self.enabled:
            self.auditor.log_database_operation(
                operation, table, user, affected_rows, query, success, error
            )
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get database security summary"""
        if not self.enabled:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "field_encryption": {
                "enabled": self.field_encryption.enabled,
                "encrypted_fields_count": len(self.field_encryption.encrypted_fields)
            },
            "injection_detection": {
                "enabled": self.injection_detector.enabled
            },
            "auditing": {
                "enabled": self.auditor.enabled,
                "audit_log_size": len(self.auditor.audit_log),
                "recent_summary": self.auditor.get_audit_summary()
            }
        }


class SecurityError(Exception):
    """Database security error"""
    pass


# Global database security manager
database_security_manager = DatabaseSecurityManager()


def get_database_security_manager() -> DatabaseSecurityManager:
    """Get global database security manager"""
    return database_security_manager


def secure_query_input(query: str, params: Dict[str, Any] = None, 
                      user: str = None) -> Tuple[str, Dict[str, Any]]:
    """Secure query input"""
    return database_security_manager.secure_query_input(query, params, user)


def secure_data_output(data: Dict[str, Any]) -> Dict[str, Any]:
    """Secure data output"""
    return database_security_manager.secure_data_output(data)


def log_database_operation(operation: str, table: str, user: str = None,
                         affected_rows: int = 0, query: str = None,
                         success: bool = True, error: str = None):
    """Log database operation"""
    database_security_manager.log_operation(
        operation, table, user, affected_rows, query, success, error
    )


def get_database_security_summary() -> Dict[str, Any]:
    """Get database security summary"""
    return database_security_manager.get_security_summary()
