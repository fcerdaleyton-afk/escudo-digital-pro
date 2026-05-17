"""
Security Tests for Mary V5 Enterprise
Comprehensive security testing suite
"""

import pytest
import asyncio
import json
import time
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import modules to test
from app.security.advanced_middleware import (
    AdvancedSecurityMiddleware, IPReputationFilter, 
    RequestFingerprinter, ThreatScoringEngine, AdvancedRateLimiter
)
from app.detection.threat_engine import (
    ThreatDetectionEngine, ThreatType, ThreatSeverity
)
from app.auth.zero_trust import (
    ZeroTrustAuthManager, DeviceTrustLevel, SessionStatus
)
from app.security.database_security import (
    DatabaseSecurityManager, SQLInjectionDetector
)
from app.services.enterprise_features import (
    EnterpriseManager, AuditEventType, ComplianceStandard
)


class TestAdvancedSecurityMiddleware:
    """Test advanced security middleware"""
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request"""
        request = Mock()
        request.method = "GET"
        request.url.path = "/api/test"
        request.url.query = ""
        request.headers = {
            "user-agent": "Mozilla/5.0 Test Browser",
            "x-forwarded-for": "192.168.1.100"
        }
        request.client.host = "192.168.1.100"
        return request
    
    @pytest.fixture
    def security_middleware(self):
        """Create security middleware instance"""
        app = Mock()
        return AdvancedSecurityMiddleware(app)
    
    def test_ip_reputation_filter(self):
        """Test IP reputation filtering"""
        filter = IPReputationFilter()
        
        # Test normal IP
        reputation = filter.get_ip_reputation("192.168.1.100")
        assert reputation["score"] >= 0
        assert "ip" in reputation
        assert "score" in reputation
    
    def test_request_fingerprinting(self, mock_request):
        """Test request fingerprinting"""
        fingerprinter = RequestFingerprinter()
        
        # Generate fingerprint
        fingerprint = fingerprinter.generate_fingerprint(mock_request)
        assert len(fingerprint) == 32  # SHA256 hash length
        
        # Test replay attack detection
        is_replay = fingerprinter.check_replay_attack(fingerprint, "192.168.1.100")
        assert isinstance(is_replay, bool)
    
    def test_threat_scoring_engine(self, mock_request):
        """Test threat scoring engine"""
        scorer = ThreatScoringEngine()
        
        ip_info = {"score": 30, "is_suspicious": False}
        fingerprint_check = False
        rate_limit_status = {"exceeded": False}
        
        threat_score = scorer.calculate_threat_score(
            mock_request, ip_info, fingerprint_check, rate_limit_status
        )
        
        assert "score" in threat_score
        assert "risk_level" in threat_score
        assert "factors" in threat_score
        assert threat_score["risk_level"] in ["low", "medium", "high", "critical"]
    
    @pytest.mark.asyncio
    async def test_advanced_rate_limiter(self):
        """Test advanced rate limiting"""
        limiter = AdvancedRateLimiter()
        await limiter.initialize()
        
        # Test rate limit check
        result = await limiter.check_rate_limit("test_key", "ip")
        
        assert "allowed" in result
        assert "remaining" in result
        assert "reset_time" in result


class TestThreatDetectionEngine:
    """Test threat detection engine"""
    
    @pytest.fixture
    def threat_engine(self):
        """Create threat detection engine"""
        return ThreatDetectionEngine()
    
    @pytest.mark.asyncio
    async def test_ransomware_detection(self, threat_engine):
        """Test ransomware detection"""
        threats = await threat_engine.ransomware_detector.detect_ransomware_activity()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    @pytest.mark.asyncio
    async def test_malware_detection(self, threat_engine):
        """Test malware detection"""
        threats = await threat_engine.malware_detector.detect_malware_activity()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    def test_threat_summary(self, threat_engine):
        """Test threat summary"""
        summary = threat_engine.get_threat_summary()
        
        assert "total_threats" in summary
        assert "enabled" in summary
        assert "detection_interval" in summary


class TestZeroTrustAuth:
    """Test zero-trust authentication"""
    
    @pytest.fixture
    def auth_manager(self):
        """Create zero-trust auth manager"""
        return ZeroTrustAuthManager()
    
    def test_device_fingerprinting(self, auth_manager):
        """Test device fingerprinting"""
        request_data = {
            "user_agent": "Mozilla/5.0 Test Browser",
            "ip_address": "192.168.1.100",
            "platform": "Windows"
        }
        
        device = auth_manager.device_fingerprinting.generate_device_fingerprint(request_data)
        
        assert device.device_id
        assert device.user_agent
        assert device.ip_address
        assert device.trust_level in DeviceTrustLevel
    
    @pytest.mark.asyncio
    async def test_token_rotation(self, auth_manager):
        """Test token rotation"""
        access_token, refresh_token = auth_manager.token_manager.generate_token_pair(
            "user123", "device123"
        )
        
        assert access_token
        assert refresh_token
        
        # Validate access token
        claims = auth_manager.token_manager.validate_token(access_token, "access")
        assert claims["valid"]
        assert claims["user_id"] == "user123"
        
        # Test token rotation
        new_access_token = auth_manager.token_manager.rotate_access_token(refresh_token)
        assert new_access_token
    
    @pytest.mark.asyncio
    async def test_session_validation(self, auth_manager):
        """Test continuous session validation"""
        session = auth_manager.continuous_validator.create_session(
            "user123", "device123", 0.8
        )
        
        assert session.session_id
        assert session.user_id == "user123"
        assert session.device_id == "device123"
        assert session.trust_score == 0.8
        assert session.status == SessionStatus.ACTIVE
        
        # Validate session
        validation = auth_manager.continuous_validator.validate_session(
            session.session_id
        )
        
        assert validation["valid"]
        assert "trust_score" in validation


class TestDatabaseSecurity:
    """Test database security"""
    
    @pytest.fixture
    def db_security(self):
        """Create database security manager"""
        return DatabaseSecurityManager()
    
    def test_field_encryption(self, db_security):
        """Test field encryption"""
        # Test encryption
        sensitive_data = "password123"
        encrypted = db_security.field_encryption.encrypt_field("password", sensitive_data)
        
        assert encrypted != sensitive_data
        assert isinstance(encrypted, str)
        
        # Test decryption
        decrypted = db_security.field_encryption.decrypt_field("password", encrypted)
        assert decrypted == sensitive_data
    
    def test_sql_injection_detection(self, db_security):
        """Test SQL injection detection"""
        detector = db_security.injection_detector
        
        # Test normal input
        normal_input = "username123"
        result = detector.detect_injection(normal_input)
        assert not result["detected"]
        assert result["risk_score"] == 0
        
        # Test malicious input
        malicious_input = "'; DROP TABLE users; --"
        result = detector.detect_injection(malicious_input)
        assert result["detected"]
        assert result["risk_score"] > 0
        assert result["risk_level"] in ["low", "medium", "high"]
    
    def test_query_sanitization(self, db_security):
        """Test query input sanitization"""
        malicious_query = "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
        sanitized = db_security.injection_detector.sanitize_input(malicious_query)
        
        assert ";" not in sanitized
        assert "--" not in sanitized
    
    def test_database_auditing(self, db_security):
        """Test database operation auditing"""
        db_security.auditor.log_database_operation(
            "SELECT", "users", "admin", 5, "SELECT * FROM users", True
        )
        
        # Check audit log
        recent_ops = db_security.auditor.get_recent_operations(10)
        assert len(recent_ops) > 0
        
        last_op = recent_ops[-1]
        assert last_op["operation"] == "SELECT"
        assert last_op["table"] == "users"
        assert last_op["user"] == "admin"


class TestEnterpriseFeatures:
    """Test enterprise features"""
    
    @pytest.fixture
    def enterprise_manager(self):
        """Create enterprise manager"""
        return EnterpriseManager()
    
    def test_structured_logging(self, enterprise_manager):
        """Test structured logging"""
        enterprise_manager.log_structured_event(
            "INFO", "user_login", "User logged in successfully",
            user_id="user123", correlation_id="corr456"
        )
        
        # Check log stats
        stats = enterprise_manager.structured_logger.get_log_stats()
        assert stats["total_logs"] > 0
        assert "INFO" in stats["by_level"]
    
    def test_audit_recording(self, enterprise_manager):
        """Test audit event recording"""
        enterprise_manager.record_audit_event(
            AuditEventType.USER_AUTHENTICATION,
            user_id="user123",
            resource="login",
            action="authenticate",
            result="success"
        )
        
        # Check audit summary
        summary = enterprise_manager.audit_manager.get_audit_summary(1)
        assert summary["total_events"] > 0
    
    @pytest.mark.asyncio
    async def test_health_checks(self, enterprise_manager):
        """Test health checks"""
        health_status = await enterprise_manager.run_health_checks()
        
        assert "status" in health_status
        assert "timestamp" in health_status
        assert "components" in health_status
    
    def test_compliance_reporting(self, enterprise_manager):
        """Test compliance reporting"""
        period_start = datetime.utcnow() - timedelta(days=30)
        period_end = datetime.utcnow()
        
        report = enterprise_manager.audit_manager.generate_compliance_report(
            ComplianceStandard.GDPR, period_start, period_end
        )
        
        assert report.standard == ComplianceStandard.GDPR
        assert report.compliance_score >= 0
        assert report.compliance_score <= 100
        assert isinstance(report.violations, list)
        assert isinstance(report.recommendations, list)


class TestSecurityIntegration:
    """Integration tests for security components"""
    
    @pytest.mark.asyncio
    async def test_full_security_pipeline(self):
        """Test complete security pipeline"""
        # Create mock request
        request = Mock()
        request.method = "POST"
        request.url.path = "/api/v1/auth/login"
        request.url.query = ""
        request.headers = {
            "user-agent": "Mozilla/5.0 Test Browser",
            "content-type": "application/json"
        }
        request.client.host = "192.168.1.100"
        
        # Test IP reputation
        ip_filter = IPReputationFilter()
        ip_reputation = ip_filter.get_ip_reputation("192.168.1.100")
        assert ip_reputation["score"] < 50  # Should be low for normal IP
        
        # Test request fingerprinting
        fingerprinter = RequestFingerprinter()
        fingerprint = fingerprinter.generate_fingerprint(request)
        assert len(fingerprint) == 32
        
        # Test threat scoring
        scorer = ThreatScoringEngine()
        threat_score = scorer.calculate_threat_score(
            request, ip_reputation, False, {"exceeded": False}
        )
        assert threat_score["risk_level"] == "low"
        
        # Test rate limiting
        limiter = AdvancedRateLimiter()
        await limiter.initialize()
        rate_result = await limiter.check_rate_limit("192.168.1.100:/api/v1/auth/login")
        assert rate_result["allowed"]
    
    @pytest.mark.asyncio
    async def test_zero_trust_authentication_flow(self):
        """Test zero-trust authentication flow"""
        auth_manager = ZeroTrustAuthManager()
        
        # Mock credentials and request context
        credentials = {"username": "admin", "password": "secure_password"}
        request_context = {
            "user_agent": "Mozilla/5.0 Test Browser",
            "ip_address": "192.168.1.100",
            "platform": "Windows"
        }
        
        # Test authentication
        auth_result = await auth_manager.authenticate(credentials, request_context)
        
        if auth_result["authenticated"]:
            assert "session_id" in auth_result
            assert "access_token" in auth_result
            assert "refresh_token" in auth_result
            
            # Test session validation
            session_validation = await auth_manager.validate_session(
                auth_result["access_token"], request_context
            )
            assert session_validation["valid"]
    
    def test_database_security_integration(self):
        """Test database security integration"""
        db_security = DatabaseSecurityManager()
        
        # Test query input security
        malicious_query = "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
        sanitized_query, sanitized_params = db_security.secure_query_input(
            malicious_query, {"id": 1}
        )
        
        assert ";" not in sanitized_query
        assert "DROP" not in sanitized_query
        
        # Test data output security
        sensitive_data = {
            "username": "testuser",
            "password": "secret123",
            "email": "test@example.com"
        }
        
        # Encrypt sensitive fields
        encrypted_data = db_security.field_encryption.encrypt_dict_fields(sensitive_data)
        assert encrypted_data["password"] != "secret123"
        
        # Decrypt sensitive fields
        decrypted_data = db_security.field_encryption.decrypt_dict_fields(encrypted_data)
        assert decrypted_data["password"] == "secret123"


class TestPerformanceAndLoad:
    """Performance and load tests"""
    
    @pytest.mark.asyncio
    async def test_security_middleware_performance(self):
        """Test security middleware performance under load"""
        middleware = AdvancedSecurityMiddleware(Mock())
        
        # Create mock requests
        requests = []
        for i in range(100):
            request = Mock()
            request.method = "GET"
            request.url.path = f"/api/test/{i}"
            request.headers = {"user-agent": "Test Browser"}
            request.client.host = f"192.168.1.{i % 255}"
            requests.append(request)
        
        # Measure performance
        start_time = time.time()
        
        for request in requests:
            # Test IP reputation lookup
            ip_reputation = middleware.ip_filter.get_ip_reputation(request.client.host)
            
            # Test fingerprinting
            fingerprint = middleware.fingerprinter.generate_fingerprint(request)
            
            # Test threat scoring
            threat_score = middleware.threat_scorer.calculate_threat_score(
                request, ip_reputation, False, {"exceeded": False}
            )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete 100 requests in reasonable time
        assert total_time < 5.0  # 5 seconds max
        assert total_time / 100 < 0.05  # 50ms per request max
    
    @pytest.mark.asyncio
    async def test_concurrent_threat_detection(self):
        """Test concurrent threat detection"""
        threat_engine = ThreatDetectionEngine()
        
        # Run detection concurrently
        tasks = [
            threat_engine.ransomware_detector.detect_ransomware_activity(),
            threat_engine.malware_detector.detect_malware_activity()
        ]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Should complete quickly
        assert end_time - start_time < 2.0
        assert len(results) == 2
        assert all(isinstance(result, list) for result in results)


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    @pytest.mark.asyncio
    async def test_middleware_error_handling(self):
        """Test middleware error handling"""
        middleware = AdvancedSecurityMiddleware(Mock())
        
        # Test with malformed request
        request = Mock()
        request.method = None  # Invalid method
        request.url = Mock()
        request.url.path = ""
        request.url.query = ""
        request.headers = {}
        request.client = Mock()
        request.client.host = None
        
        # Should not crash
        try:
            # This would normally call call_next, but we're testing error handling
            ip_reputation = middleware.ip_filter.get_ip_reputation("invalid_ip")
            assert isinstance(ip_reputation, dict)
        except Exception as e:
            pytest.fail(f"Middleware should handle errors gracefully: {e}")
    
    def test_encryption_edge_cases(self):
        """Test encryption edge cases"""
        db_security = DatabaseSecurityManager()
        
        # Test with empty string
        encrypted = db_security.field_encryption.encrypt_field("test", "")
        decrypted = db_security.field_encryption.decrypt_field("test", encrypted)
        assert decrypted == ""
        
        # Test with None
        encrypted = db_security.field_encryption.encrypt_field("test", None)
        assert encrypted is None
        
        # Test with non-string data
        encrypted = db_security.field_encryption.encrypt_field("test", 123)
        decrypted = db_security.field_encryption.decrypt_field("test", encrypted)
        assert decrypted == "123"
    
    def test_audit_edge_cases(self):
        """Test audit edge cases"""
        db_security = DatabaseSecurityManager()
        
        # Test with very long query
        long_query = "SELECT * FROM users WHERE name = '" + "a" * 1000 + "'"
        db_security.auditor.log_database_operation(
            "SELECT", "users", "test", 1, long_query, True
        )
        
        # Should handle gracefully
        recent_ops = db_security.auditor.get_recent_operations(1)
        assert len(recent_ops) > 0
        assert len(recent_ops[-1]["query"]) <= 500  # Should be truncated


# Test configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "asyncio: mark test to run with asyncio"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security test"
    )


if __name__ == "__main__":
    # Run tests
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-m", "security",
        "--disable-warnings"
    ])
