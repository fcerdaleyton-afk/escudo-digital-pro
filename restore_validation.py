#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Restore Validation Script
Automated restore validation and testing system
"""

import os
import sys
import asyncio
import logging
import yaml
import json
import hashlib
import gzip
import boto3
import psycopg2
import redis
import tempfile
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'app')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/restore_validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class RestoreValidator:
    """Restore validation system for MARY V5 SHIELD CORE"""
    
    def __init__(self, config_path: str = "backup_config.yaml"):
        """Initialize restore validation system"""
        self.config = self._load_config(config_path)
        self.encryption_key = None
        self.s3_client = None
        self.kms_client = None
        self._initialize_clients()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load backup configuration"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _initialize_clients(self):
        """Initialize AWS and database clients"""
        try:
            # Initialize AWS clients
            self.s3_client = boto3.client(
                's3',
                region_name=self.config['storage']['region']
            )
            self.kms_client = boto3.client(
                'kms',
                region_name=self.config['storage']['region']
            )
            
            # Initialize encryption
            self._initialize_encryption()
            
            logger.info("Clients initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize clients: {e}")
            raise
    
    def _initialize_encryption(self):
        """Initialize encryption system"""
        try:
            # Get encryption key from KMS
            key_id = self.config['encryption']['key_id']
            response = self.kms_client.generate_data_key(
                KeyId=key_id,
                KeySpec='AES_256'
            )
            
            # Use plaintext key for encryption
            self.encryption_key = response['Plaintext']
            logger.info("Encryption system initialized")
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            raise
    
    async def validate_restore(self, backup_type: str, component: str, 
                            backup_id: Optional[str] = None) -> Dict[str, Any]:
        """Validate restore process for a specific component"""
        validation_result = {
            "backup_type": backup_type,
            "component": component,
            "backup_id": backup_id,
            "start_time": datetime.utcnow(),
            "status": "in_progress",
            "tests": {},
            "errors": [],
            "success_count": 0,
            "failure_count": 0
        }
        
        try:
            logger.info(f"Starting restore validation for {component} ({backup_type})")
            
            # Get backup to restore
            if backup_id:
                backup_info = await self._get_backup_info(backup_id)
            else:
                backup_info = await self._get_latest_backup(backup_type, component)
            
            validation_result["backup_info"] = backup_info
            
            # Download and decrypt backup
            backup_data = await self._download_and_decrypt_backup(backup_info)
            
            # Run validation tests based on component type
            if component == "database":
                test_results = await self._validate_database_restore(backup_data)
            elif component == "redis":
                test_results = await self._validate_redis_restore(backup_data)
            elif component in ["configuration", "logs", "audit"]:
                test_results = await self._validate_files_restore(backup_data, component)
            else:
                raise ValueError(f"Unknown component: {component}")
            
            validation_result["tests"] = test_results
            
            # Calculate success/failure counts
            for test_name, test_result in test_results.items():
                if test_result.get("passed", False):
                    validation_result["success_count"] += 1
                else:
                    validation_result["failure_count"] += 1
                    validation_result["errors"].append(
                        f"Test {test_name}: {test_result.get('error', 'Test failed')}"
                    )
            
            # Update overall status
            if validation_result["failure_count"] == 0:
                validation_result["status"] = "success"
            elif validation_result["success_count"] > 0:
                validation_result["status"] = "partial"
            else:
                validation_result["status"] = "failed"
            
            validation_result["end_time"] = datetime.utcnow()
            validation_result["duration"] = (
                validation_result["end_time"] - validation_result["start_time"]
            ).total_seconds()
            
            logger.info(f"Restore validation completed: {validation_result['status']} - "
                       f"Success: {validation_result['success_count']}, "
                       f"Failures: {validation_result['failure_count']}")
            
            # Send notifications for failures
            if validation_result["status"] in ["failed", "partial"]:
                await self._send_validation_notifications(validation_result)
            
            # Update metrics
            await self._update_validation_metrics(validation_result)
            
        except Exception as e:
            logger.error(f"Restore validation failed: {e}")
            validation_result["status"] = "failed"
            validation_result["error"] = str(e)
            validation_result["end_time"] = datetime.utcnow()
        
        return validation_result
    
    async def _get_backup_info(self, backup_id: str) -> Dict[str, Any]:
        """Get backup information by ID"""
        try:
            # Parse backup_id to extract S3 key
            parts = backup_id.split('/')
            if len(parts) < 3:
                raise ValueError(f"Invalid backup_id format: {backup_id}")
            
            backup_type = parts[0]
            component = parts[1]
            filename = parts[2]
            
            # Get object metadata
            response = self.s3_client.head_object(
                Bucket=self.config['storage']['bucket'],
                Key=f"{backup_type}/{component}/{filename}"
            )
            
            return {
                "bucket": self.config['storage']['bucket'],
                "key": f"{backup_type}/{component}/{filename}",
                "size": response['ContentLength'],
                "metadata": response.get('Metadata', {}),
                "last_modified": response['LastModified']
            }
            
        except Exception as e:
            logger.error(f"Failed to get backup info: {e}")
            raise
    
    async def _get_latest_backup(self, backup_type: str, component: str) -> Dict[str, Any]:
        """Get latest backup for component"""
        try:
            # List objects in S3
            prefix = f"{backup_type}/{component}/"
            response = self.s3_client.list_objects_v2(
                Bucket=self.config['storage']['bucket'],
                Prefix=prefix,
                MaxKeys=1000
            )
            
            if 'Contents' not in response or not response['Contents']:
                raise ValueError(f"No backups found for {component} ({backup_type})")
            
            # Sort by last modified and get latest
            objects = sorted(
                response['Contents'],
                key=lambda x: x['LastModified'],
                reverse=True
            )
            
            latest_object = objects[0]
            
            return {
                "bucket": self.config['storage']['bucket'],
                "key": latest_object['Key'],
                "size": latest_object['Size'],
                "metadata": latest_object.get('Metadata', {}),
                "last_modified": latest_object['LastModified']
            }
            
        except Exception as e:
            logger.error(f"Failed to get latest backup: {e}")
            raise
    
    async def _download_and_decrypt_backup(self, backup_info: Dict[str, Any]) -> bytes:
        """Download and decrypt backup data"""
        try:
            # Download from S3
            response = self.s3_client.get_object(
                Bucket=backup_info['bucket'],
                Key=backup_info['key']
            )
            
            encrypted_data = response['Body'].read()
            
            # Decrypt data
            decrypted_data = self._decrypt_data(encrypted_data)
            
            # Decompress data
            decompressed_data = self._decompress_data(decrypted_data)
            
            logger.info(f"Downloaded and decrypted backup: {len(decompressed_data)} bytes")
            
            return decompressed_data
            
        except Exception as e:
            logger.error(f"Failed to download and decrypt backup: {e}")
            raise
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data using AES-256"""
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(data)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _decompress_data(self, data: bytes) -> bytes:
        """Decompress data using gzip"""
        return gzip.decompress(data)
    
    async def _validate_database_restore(self, backup_data: bytes) -> Dict[str, Any]:
        """Validate database restore"""
        test_results = {}
        
        try:
            # Test 1: SQL syntax validation
            test_results["sql_syntax"] = await self._test_sql_syntax(backup_data)
            
            # Test 2: Data integrity validation
            test_results["data_integrity"] = await self._test_data_integrity(backup_data)
            
            # Test 3: Connection test (dry run)
            test_results["connection_test"] = await self._test_database_connection()
            
            # Test 4: Performance test
            test_results["performance_test"] = await self._test_database_performance()
            
            # Test 5: Security validation
            test_results["security_test"] = await self._test_database_security()
            
        except Exception as e:
            logger.error(f"Database restore validation failed: {e}")
            test_results["error"] = str(e)
        
        return test_results
    
    async def _test_sql_syntax(self, backup_data: bytes) -> Dict[str, Any]:
        """Test SQL syntax validity"""
        try:
            # Convert bytes to string
            sql_content = backup_data.decode('utf-8')
            
            # Basic syntax checks
            syntax_errors = []
            
            # Check for common syntax issues
            if sql_content.count('(') != sql_content.count(')'):
                syntax_errors.append("Unmatched parentheses")
            
            if sql_content.count("'") % 2 != 0:
                syntax_errors.append("Unmatched quotes")
            
            # Check for COPY commands (pg_dump format)
            if "COPY " not in sql_content:
                syntax_errors.append("Missing COPY commands (not a valid pg_dump)")
            
            # Check for PostgreSQL version compatibility
            if "PostgreSQL database dump" not in sql_content:
                syntax_errors.append("Not a valid PostgreSQL dump")
            
            return {
                "passed": len(syntax_errors) == 0,
                "syntax_errors": syntax_errors,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_data_integrity(self, backup_data: bytes) -> Dict[str, Any]:
        """Test data integrity"""
        try:
            # Calculate checksum
            checksum = hashlib.sha256(backup_data).hexdigest()
            
            # Check for common corruption patterns
            corruption_indicators = []
            
            # Check for null bytes in the middle of data
            if b'\x00\x00\x00' in backup_data[100:-100]:
                corruption_indicators.append("Null bytes detected in data")
            
            # Check for truncated data
            if not backup_data.endswith(b'\n'):
                corruption_indicators.append("Data appears truncated")
            
            # Check minimum size
            if len(backup_data) < 1024:  # Less than 1KB
                corruption_indicators.append("Backup too small")
            
            return {
                "passed": len(corruption_indicators) == 0,
                "checksum": checksum,
                "size": len(backup_data),
                "corruption_indicators": corruption_indicators,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_database_connection(self) -> Dict[str, Any]:
        """Test database connection"""
        try:
            # Get database configuration
            db_config = self.config['components']['database']
            
            # Test connection
            conn = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                database=db_config['database'],
                user=db_config['user'],
                password=db_config['password'],
                connect_timeout=30
            )
            
            # Test query
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            
            conn.close()
            
            return {
                "passed": result[0] == 1,
                "connection_time": "< 30 seconds",
                "test_query": "SELECT 1",
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_database_performance(self) -> Dict[str, Any]:
        """Test database performance"""
        try:
            # Get database configuration
            db_config = self.config['components']['database']
            
            # Test connection and query performance
            start_time = datetime.utcnow()
            
            conn = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                database=db_config['database'],
                user=db_config['user'],
                password=db_config['password']
            )
            
            cursor = conn.cursor()
            
            # Test simple query
            cursor.execute("SELECT COUNT(*) FROM pg_stat_activity")
            cursor.fetchone()
            
            # Test table count
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
            cursor.fetchone()
            
            conn.close()
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "passed": duration < 5.0,  # Less than 5 seconds
                "duration": duration,
                "threshold": 5.0,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_database_security(self) -> Dict[str, Any]:
        """Test database security"""
        try:
            # Get database configuration
            db_config = self.config['components']['database']
            
            conn = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                database=db_config['database'],
                user=db_config['user'],
                password=db_config['password']
            )
            
            cursor = conn.cursor()
            
            # Check for SSL connection
            cursor.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            ssl_result = cursor.fetchone()
            
            # Check for encryption
            cursor.execute("SELECT setting FROM pg_settings WHERE name = 'ssl'")
            ssl_setting = cursor.fetchone()
            
            conn.close()
            
            ssl_enabled = ssl_result and ssl_result[0] == 't'
            ssl_configured = ssl_setting and ssl_setting[0] in ['require', 'verify-ca', 'verify-full']
            
            return {
                "passed": ssl_enabled and ssl_configured,
                "ssl_enabled": ssl_enabled,
                "ssl_configured": ssl_configured,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _validate_redis_restore(self, backup_data: bytes) -> Dict[str, Any]:
        """Validate Redis restore"""
        test_results = {}
        
        try:
            # Test 1: RDB format validation
            test_results["rdb_format"] = await self._test_rdb_format(backup_data)
            
            # Test 2: Data integrity
            test_results["data_integrity"] = await self._test_redis_data_integrity(backup_data)
            
            # Test 3: Connection test
            test_results["connection_test"] = await self._test_redis_connection()
            
            # Test 4: Performance test
            test_results["performance_test"] = await self._test_redis_performance()
            
            # Test 5: Security validation
            test_results["security_test"] = await self._test_redis_security()
            
        except Exception as e:
            logger.error(f"Redis restore validation failed: {e}")
            test_results["error"] = str(e)
        
        return test_results
    
    async def _test_rdb_format(self, backup_data: bytes) -> Dict[str, Any]:
        """Test RDB format validity"""
        try:
            # Check RDB magic number
            if not backup_data.startswith(b"REDIS"):
                return {
                    "passed": False,
                    "error": "Invalid RDB format - missing magic number",
                    "validation_time": datetime.utcnow().isoformat()
                }
            
            # Check RDB version
            if len(backup_data) < 9:
                return {
                    "passed": False,
                    "error": "Invalid RDB format - too short",
                    "validation_time": datetime.utcnow().isoformat()
                }
            
            # Extract version
            version = int.from_bytes(backup_data[4:8], byteorder='little')
            
            return {
                "passed": version >= 7,  # Redis 7.0+
                "version": version,
                "magic_number": backup_data[:5].decode('ascii'),
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_redis_data_integrity(self, backup_data: bytes) -> Dict[str, Any]:
        """Test Redis data integrity"""
        try:
            # Calculate checksum
            checksum = hashlib.sha256(backup_data).hexdigest()
            
            # Check for corruption indicators
            corruption_indicators = []
            
            # Check minimum size
            if len(backup_data) < 1024:  # Less than 1KB
                corruption_indicators.append("Backup too small")
            
            # Check for EOF marker
            if not backup_data.endswith(b"\xff"):
                corruption_indicators.append("Missing EOF marker")
            
            return {
                "passed": len(corruption_indicators) == 0,
                "checksum": checksum,
                "size": len(backup_data),
                "corruption_indicators": corruption_indicators,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_redis_connection(self) -> Dict[str, Any]:
        """Test Redis connection"""
        try:
            # Get Redis configuration
            redis_config = self.config['components']['redis']
            
            # Test connection
            r = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                password=redis_config.get('password'),
                db=redis_config.get('database', 0),
                socket_timeout=10
            )
            
            # Test ping
            pong = r.ping()
            
            # Test info
            info = r.info()
            
            return {
                "passed": pong,
                "ping_response": pong,
                "redis_version": info.get('redis_version'),
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_redis_performance(self) -> Dict[str, Any]:
        """Test Redis performance"""
        try:
            # Get Redis configuration
            redis_config = self.config['components']['redis']
            
            r = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                password=redis_config.get('password'),
                db=redis_config.get('database', 0)
            )
            
            # Test set/get performance
            start_time = datetime.utcnow()
            
            test_key = f"test_performance_{int(start_time.timestamp())}"
            r.set(test_key, "test_value")
            result = r.get(test_key)
            r.delete(test_key)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "passed": duration < 1.0 and result == b"test_value",
                "duration": duration,
                "threshold": 1.0,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_redis_security(self) -> Dict[str, Any]:
        """Test Redis security"""
        try:
            # Get Redis configuration
            redis_config = self.config['components']['redis']
            
            r = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                password=redis_config.get('password'),
                db=redis_config.get('database', 0)
            )
            
            # Check if password is required
            try:
                # Try to connect without password
                r_no_auth = redis.Redis(
                    host=redis_config['host'],
                    port=redis_config['port'],
                    db=redis_config.get('database', 0),
                    socket_timeout=5
                )
                r_no_auth.ping()
                auth_required = False
            except:
                auth_required = True
            
            # Check SSL/TLS (if configured)
            info = r.info()
            tls_enabled = 'tcp_port' in info and info.get('tcp_port') != 6379
            
            return {
                "passed": auth_required,  # Require authentication
                "auth_required": auth_required,
                "tls_enabled": tls_enabled,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _validate_files_restore(self, backup_data: bytes, component: str) -> Dict[str, Any]:
        """Validate files restore"""
        test_results = {}
        
        try:
            # Test 1: Archive format validation
            test_results["archive_format"] = await self._test_archive_format(backup_data)
            
            # Test 2: File integrity
            test_results["file_integrity"] = await self._test_file_integrity(backup_data)
            
            # Test 3: Content validation
            test_results["content_validation"] = await self._test_content_validation(backup_data, component)
            
            # Test 4: Security validation
            test_results["security_validation"] = await self._test_file_security(backup_data, component)
            
        except Exception as e:
            logger.error(f"Files restore validation failed: {e}")
            test_results["error"] = str(e)
        
        return test_results
    
    async def _test_archive_format(self, backup_data: bytes) -> Dict[str, Any]:
        """Test archive format validity"""
        try:
            import tarfile
            
            # Create temporary file
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(backup_data)
                temp_file.flush()
                
                # Try to open as tar file
                with tarfile.open(temp_file.name, 'r') as tar:
                    members = tar.getmembers()
                    
                    return {
                        "passed": len(members) > 0,
                        "file_count": len(members),
                        "archive_format": "tar",
                        "validation_time": datetime.utcnow().isoformat()
                    }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_file_integrity(self, backup_data: bytes) -> Dict[str, Any]:
        """Test file integrity"""
        try:
            # Calculate checksum
            checksum = hashlib.sha256(backup_data).hexdigest()
            
            # Check for corruption indicators
            corruption_indicators = []
            
            # Check minimum size
            if len(backup_data) < 1024:  # Less than 1KB
                corruption_indicators.append("Archive too small")
            
            return {
                "passed": len(corruption_indicators) == 0,
                "checksum": checksum,
                "size": len(backup_data),
                "corruption_indicators": corruption_indicators,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_content_validation(self, backup_data: bytes, component: str) -> Dict[str, Any]:
        """Test content validity"""
        try:
            import tarfile
            
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(backup_data)
                temp_file.flush()
                
                with tarfile.open(temp_file.name, 'r') as tar:
                    members = tar.getmembers()
                    
                    # Validate based on component type
                    if component == "configuration":
                        return await self._validate_config_content(tar, members)
                    elif component == "logs":
                        return await self._validate_log_content(tar, members)
                    elif component == "audit":
                        return await self._validate_audit_content(tar, members)
                    else:
                        return {
                            "passed": True,
                            "file_count": len(members),
                            "validation_time": datetime.utcnow().isoformat()
                        }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _validate_config_content(self, tar, members) -> Dict[str, Any]:
        """Validate configuration content"""
        try:
            valid_files = 0
            invalid_files = 0
            
            for member in members:
                if member.name.endswith(('.yaml', '.yml', '.json', '.env')):
                    # Extract and validate file
                    f = tar.extractfile(member)
                    content = f.read().decode('utf-8')
                    
                    # Basic validation
                    if len(content) > 0:
                        valid_files += 1
                    else:
                        invalid_files += 1
            
            return {
                "passed": valid_files > 0 and invalid_files == 0,
                "valid_files": valid_files,
                "invalid_files": invalid_files,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _validate_log_content(self, tar, members) -> Dict[str, Any]:
        """Validate log content"""
        try:
            valid_files = 0
            invalid_files = 0
            
            for member in members:
                if member.name.endswith(('.log', '.json')):
                    # Extract and validate file
                    f = tar.extractfile(member)
                    content = f.read().decode('utf-8')
                    
                    # Basic validation
                    if len(content) > 0 and len(content.split('\n')) > 1:
                        valid_files += 1
                    else:
                        invalid_files += 1
            
            return {
                "passed": valid_files > 0,
                "valid_files": valid_files,
                "invalid_files": invalid_files,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _validate_audit_content(self, tar, members) -> Dict[str, Any]:
        """Validate audit content"""
        try:
            valid_files = 0
            invalid_files = 0
            
            for member in members:
                if member.name.endswith(('.json', '.csv', '.xml')):
                    # Extract and validate file
                    f = tar.extractfile(member)
                    content = f.read().decode('utf-8')
                    
                    # Basic validation
                    if len(content) > 0:
                        valid_files += 1
                    else:
                        invalid_files += 1
            
            return {
                "passed": valid_files > 0,
                "valid_files": valid_files,
                "invalid_files": invalid_files,
                "validation_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _test_file_security(self, backup_data: bytes, component: str) -> Dict[str, Any]:
        """Test file security"""
        try:
            import tarfile
            
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(backup_data)
                temp_file.flush()
                
                with tarfile.open(temp_file.name, 'r') as tar:
                    members = tar.getmembers()
                    
                    # Check for security issues
                    security_issues = []
                    
                    for member in members:
                        # Check for executable files
                        if member.mode & 0o111:
                            security_issues.append(f"Executable file: {member.name}")
                        
                        # Check for world-writable files
                        if member.mode & 0o002:
                            security_issues.append(f"World-writable file: {member.name}")
                        
                        # Check for suspicious file names
                        if any(name in member.name.lower() for name in ['password', 'key', 'secret', 'token']):
                            security_issues.append(f"Suspicious file name: {member.name}")
                    
                    return {
                        "passed": len(security_issues) == 0,
                        "security_issues": security_issues,
                        "validation_time": datetime.utcnow().isoformat()
                    }
            
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "validation_time": datetime.utcnow().isoformat()
            }
    
    async def _send_validation_notifications(self, validation_result: Dict[str, Any]):
        """Send validation notifications"""
        try:
            if not self.config['notification']['enabled']:
                return
            
            # Send email notification
            if self.config['notification']['email']['enabled']:
                await self._send_validation_email(validation_result)
            
            # Send Slack notification
            if self.config['notification']['slack']['enabled']:
                await self._send_validation_slack(validation_result)
                
        except Exception as e:
            logger.error(f"Failed to send validation notifications: {e}")
    
    async def _send_validation_email(self, validation_result: Dict[str, Any]):
        """Send validation email notification"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.config['notification']['email']['from_email']
            msg['To'] = ', '.join(self.config['notification']['email']['to_emails'])
            msg['Subject'] = f"MARY V5 Restore Validation {validation_result['status'].upper()}: {validation_result['component']}"
            
            # Create email body
            body = f"""
MARY V5 SHIELD CORE Restore Validation Report

Component: {validation_result['component']}
Backup Type: {validation_result['backup_type']}
Status: {validation_result['status'].upper()}
Start Time: {validation_result['start_time']}
End Time: {validation_result.get('end_time', 'N/A')}
Duration: {validation_result.get('duration', 'N/A')} seconds

Test Results:
Success: {validation_result['success_count']}
Failures: {validation_result['failure_count']}

Test Details:
"""
            
            for test_name, test_result in validation_result['tests'].items():
                body += f"\n{test_name}: {test_result.get('passed', False)}"
                if not test_result.get('passed', False):
                    body += f" - Error: {test_result.get('error', 'Test failed')}"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(
                self.config['notification']['email']['smtp_host'],
                self.config['notification']['email']['smtp_port']
            ) as server:
                server.starttls()
                server.login(
                    self.config['notification']['email']['smtp_username'],
                    self.config['notification']['email']['smtp_password']
                )
                server.send_message(msg)
            
            logger.info("Validation email notification sent")
            
        except Exception as e:
            logger.error(f"Failed to send validation email: {e}")
    
    async def _send_validation_slack(self, validation_result: Dict[str, Any]):
        """Send validation Slack notification"""
        try:
            import requests
            
            # Create Slack message
            color = "good" if validation_result['status'] == "success" else "warning" if validation_result['status'] == "partial" else "danger"
            
            message = {
                "username": "Mary V5 Restore Validator",
                "icon_emoji": ":shield:",
                "channel": self.config['notification']['slack']['channel'],
                "attachments": [{
                    "color": color,
                    "title": f"MARY V5 Restore Validation {validation_result['status'].upper()}: {validation_result['component']}",
                    "fields": [
                        {"title": "Status", "value": validation_result['status'].upper(), "short": True},
                        {"title": "Duration", "value": f"{validation_result.get('duration', 'N/A')} seconds", "short": True},
                        {"title": "Success", "value": str(validation_result['success_count']), "short": True},
                        {"title": "Failures", "value": str(validation_result['failure_count']), "short": True}
                    ],
                    "timestamp": datetime.utcnow().timestamp()
                }]
            }
            
            # Send to Slack
            response = requests.post(
                self.config['notification']['slack']['webhook_url'],
                json=message,
                timeout=30
            )
            
            response.raise_for_status()
            logger.info("Validation Slack notification sent")
            
        except Exception as e:
            logger.error(f"Failed to send validation Slack: {e}")
    
    async def _update_validation_metrics(self, validation_result: Dict[str, Any]):
        """Update validation metrics"""
        try:
            # Update Prometheus metrics
            if self.config['monitoring']['enabled']:
                from prometheus_client import Counter, Histogram
                
                # Define metrics
                validation_counter = Counter('mary_v5_restore_validation_total', 'Total restore validations', ['component', 'status'])
                validation_duration = Histogram('mary_v5_restore_validation_duration_seconds', 'Restore validation duration', ['component'])
                
                # Update metrics
                validation_counter.labels(
                    component=validation_result['component'],
                    status=validation_result['status']
                ).inc()
                
                validation_duration.labels(component=validation_result['component']).observe(
                    validation_result.get('duration', 0)
                )
            
            logger.info("Validation metrics updated")
            
        except Exception as e:
            logger.error(f"Failed to update validation metrics: {e}")


async def main():
    """Main function to run restore validation"""
    try:
        # Initialize validation system
        validator = RestoreValidator()
        
        # Get parameters from command line
        if len(sys.argv) < 3:
            print("Usage: python restore_validation.py <backup_type> <component> [backup_id]")
            sys.exit(1)
        
        backup_type = sys.argv[1]
        component = sys.argv[2]
        backup_id = sys.argv[3] if len(sys.argv) > 3 else None
        
        # Run validation
        result = await validator.validate_restore(backup_type, component, backup_id)
        
        # Exit with appropriate code
        if result['status'] == 'success':
            logger.info("Restore validation completed successfully")
            sys.exit(0)
        elif result['status'] == 'partial':
            logger.warning("Restore validation completed with partial failures")
            sys.exit(1)
        else:
            logger.error("Restore validation failed")
            sys.exit(2)
            
    except Exception as e:
        logger.error(f"Restore validation failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())
