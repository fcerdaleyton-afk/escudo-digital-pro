"""
TLS Configuration Validator for Mary V5
Production-ready TLS/SSL validation and hardening
"""

import os
import ssl
import socket
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

from app.core.dependencies import logger


class TLSValidator:
    """
    TLS configuration validator for production security
    """
    
    def __init__(self):
        self.enabled = os.getenv("TLS_VALIDATION_ENABLED", "true").lower() == "true"
        
        # TLS configuration
        self.min_tls_version = os.getenv("MIN_TLS_VERSION", "1.2")
        self.allowed_ciphers = self._load_allowed_ciphers()
        self.hsts_max_age = int(os.getenv("HSTS_MAX_AGE", "31536000"))  # 1 year
        self.require_hsts = os.getenv("REQUIRE_HSTS", "true").lower() == "true"
        self.require_ocsp = os.getenv("REQUIRE_OCSP", "true").lower() == "true"
        
        # Certificate validation
        self.cert_check_interval = int(os.getenv("CERT_CHECK_INTERVAL", "86400"))  # 24 hours
        self.cert_expiry_threshold = int(os.getenv("CERT_EXPIRY_THRESHOLD", "30"))  # 30 days
        
        # Test endpoints
        self.test_endpoints = [
            "https://localhost:8000",
            "https://mary-v5.example.com",
            os.getenv("PRODUCTION_URL", "")
        ]
        
        logger.info("TLS validator initialized", enabled=self.enabled)
    
    def _load_allowed_ciphers(self) -> List[str]:
        """Load allowed TLS ciphers"""
        default_ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256"
        ]
        
        env_ciphers = os.getenv("ALLOWED_CIPHERS", "")
        if env_ciphers:
            return [cipher.strip() for cipher in env_ciphers.split(",") if cipher.strip()]
        
        return default_ciphers
    
    async def validate_tls_configuration(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Validate TLS configuration of a service"""
        if not self.enabled:
            return {"status": "disabled", "message": "TLS validation is disabled"}
        
        validation_results = {
            "hostname": hostname,
            "port": port,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {}
        }
        
        try:
            # Create SSL context with secure settings
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers(":".join(self.allowed_ciphers))
            
            # Connect and validate
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context),
                timeout=10.0
            )
            
            # Get certificate information
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                cert = ssl_object.getpeercert()
                if cert:
                    validation_results["checks"]["certificate"] = await self._validate_certificate(cert)
            
            # Get cipher information
            cipher = writer.get_extra_info("cipher")
            if cipher:
                validation_results["checks"]["cipher"] = {
                    "name": cipher.name,
                    "version": cipher.version,
                    "bits": cipher.bits,
                    "strength": self._assess_cipher_strength(cipher)
                }
            
            # Get TLS version
            tls_version = writer.get_extra_info("tls_version")
            if tls_version:
                validation_results["checks"]["tls_version"] = {
                    "version": tls_version,
                    "minimum_met": tls_version >= self.min_tls_version,
                    "secure": tls_version >= ssl.TLSVersion.TLSv1_2
                }
            
            # Check OCSP stapling
            ocsp_response = writer.get_extra_info("ocsp_response")
            validation_results["checks"]["ocsp_stapling"] = {
                "supported": ocsp_response is not None,
                "required": self.require_ocsp
            }
            
            writer.close()
            await writer.wait_closed()
            
            validation_results["status"] = "success"
            validation_results["overall_security"] = self._calculate_overall_security(validation_results["checks"])
            
        except Exception as e:
            validation_results["status"] = "error"
            validation_results["error"] = str(e)
            logger.error("TLS validation failed", hostname=hostname, error=str(e))
        
        return validation_results
    
    async def _validate_certificate(self, cert: dict) -> Dict[str, Any]:
        """Validate SSL certificate"""
        cert_info = {}
        
        # Check expiration
        if hasattr(cert, 'getNotAfter'):
            expiry_date = cert.getNotAfter()
            days_until_expiry = (expiry_date - datetime.utcnow()).days
            
            cert_info["expiry"] = {
                "date": expiry_date.isoformat() if expiry_date else None,
                "days_until_expiry": days_until_expiry,
                "status": "valid" if days_until_expiry > self.cert_expiry_threshold else "expiring_soon",
                "threshold_met": days_until_expiry > self.cert_expiry_threshold
            }
        
        # Check issuer
        if hasattr(cert, 'getIssuer'):
            issuer = cert.getIssuer()
            cert_info["issuer"] = {
                "common_name": issuer.CN if issuer else None,
                "organization": issuer.O if issuer else None
            }
        
        # Check subject
        if hasattr(cert, 'getSubject'):
            subject = cert.getSubject()
            cert_info["subject"] = {
                "common_name": subject.CN if subject else None,
                "organization": subject.O if subject else None
            }
        
        # Check signature algorithm
        if hasattr(cert, 'getSignatureAlgorithm'):
            sig_algorithm = cert.getSignatureAlgorithm()
            cert_info["signature_algorithm"] = {
                "name": sig_algorithm.__class__.__name__ if sig_algorithm else None,
                "strength": self._assess_signature_strength(sig_algorithm)
            }
        
        # Check key size
        if hasattr(cert, 'get_pubkey'):
            pub_key = cert.get_pubkey()
            if pub_key:
                key_size = pub_key.size() if hasattr(pub_key, 'size') else None
                cert_info["key_size"] = {
                    "bits": key_size,
                    "strength": self._assess_key_strength(key_size)
                }
        
        return cert_info
    
    def _assess_cipher_strength(self, cipher) -> str:
        """Assess cipher strength"""
        if not cipher:
            return "unknown"
        
        # Check key size
        if hasattr(cipher, 'bits') and cipher.bits >= 256:
            return "strong"
        elif hasattr(cipher, 'bits') and cipher.bits >= 128:
            return "medium"
        else:
            return "weak"
    
    def _assess_signature_strength(self, algorithm) -> str:
        """Assess signature algorithm strength"""
        if not algorithm:
            return "unknown"
        
        algo_name = algorithm.__class__.__name__.upper()
        
        strong_algos = ["SHA256", "SHA384", "SHA512", "ECDSA", "RSA"]
        medium_algos = ["SHA1", "DSA"]
        
        if any(strong in algo_name for strong in strong_algos):
            return "strong"
        elif any(medium in algo_name for medium in medium_algos):
            return "medium"
        else:
            return "weak"
    
    def _assess_key_strength(self, key_size: int) -> str:
        """Assess RSA key strength"""
        if key_size >= 4096:
            return "strong"
        elif key_size >= 2048:
            return "medium"
        else:
            return "weak"
    
    def _calculate_overall_security(self, checks: Dict[str, Any]) -> str:
        """Calculate overall security score"""
        score = 100
        
        # Deduct points for issues
        if checks.get("certificate", {}).get("status") == "expiring_soon":
            score -= 20
        
        if checks.get("certificate", {}).get("threshold_met") is False:
            score -= 30
        
        if checks.get("certificate", {}).get("signature_algorithm", {}).get("strength") == "weak":
            score -= 25
        
        if checks.get("certificate", {}).get("key_size", {}).get("strength") == "weak":
            score -= 25
        
        if checks.get("tls_version", {}).get("minimum_met") is False:
            score -= 40
        
        if checks.get("cipher", {}).get("strength") == "weak":
            score -= 20
        
        if score >= 90:
            return "excellent"
        elif score >= 80:
            return "good"
        elif score >= 70:
            return "fair"
        elif score >= 60:
            return "poor"
        else:
            return "bad"
    
    async def validate_all_endpoints(self) -> List[Dict[str, Any]]:
        """Validate TLS configuration for all endpoints"""
        results = []
        
        for endpoint in self.test_endpoints:
            if not endpoint:
                continue
                
            try:
                # Extract hostname from URL
                from urllib.parse import urlparse
                parsed = urlparse(endpoint)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                
                if hostname:
                    result = await self.validate_tls_configuration(hostname, port)
                    result["endpoint"] = endpoint
                    results.append(result)
                    
            except Exception as e:
                logger.error("Endpoint validation failed", endpoint=endpoint, error=str(e))
                results.append({
                    "endpoint": endpoint,
                    "status": "error",
                    "error": str(e)
                })
        
        return results
    
    def get_tls_recommendations(self, validation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get TLS security recommendations"""
        recommendations = []
        
        # Certificate recommendations
        cert_checks = validation_results.get("checks", {}).get("certificate", {})
        
        if cert_checks.get("status") == "expiring_soon":
            recommendations.append({
                "category": "certificate",
                "priority": "high",
                "recommendation": "Renew SSL certificate before expiration",
                "details": f"Certificate expires in {cert_checks.get('days_until_expiry', 0)} days"
            })
        
        if cert_checks.get("threshold_met") is False:
            recommendations.append({
                "category": "certificate",
                "priority": "critical",
                "recommendation": "Use longer certificate validity period (365+ days)",
                "details": "Current certificate may expire too soon"
            })
        
        if cert_checks.get("signature_algorithm", {}).get("strength") == "weak":
            recommendations.append({
                "category": "certificate",
                "priority": "high",
                "recommendation": "Use SHA-256 or stronger signature algorithm",
                "details": f"Current algorithm: {cert_checks.get('signature_algorithm', {}).get('name', 'unknown')}"
            })
        
        if cert_checks.get("key_size", {}).get("strength") == "weak":
            recommendations.append({
                "category": "certificate",
                "priority": "high",
                "recommendation": "Use RSA 2048-bit or larger keys",
                "details": f"Current key size: {cert_checks.get('key_size', {}).get('bits', 'unknown')} bits"
            })
        
        # TLS version recommendations
        tls_checks = validation_results.get("checks", {}).get("tls_version", {})
        
        if tls_checks.get("minimum_met") is False:
            recommendations.append({
                "category": "tls_version",
                "priority": "critical",
                "recommendation": "Disable TLS versions below 1.2",
                "details": f"Current version: {tls_checks.get('version', 'unknown')}"
            })
        
        # Cipher recommendations
        cipher_checks = validation_results.get("checks", {}).get("cipher", {})
        
        if cipher_checks.get("strength") == "weak":
            recommendations.append({
                "category": "cipher",
                "priority": "medium",
                "recommendation": "Use stronger cipher suites",
                "details": f"Current cipher: {cipher_checks.get('name', 'unknown')}"
            })
        
        return recommendations
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get TLS validation summary"""
        return {
            "enabled": self.enabled,
            "min_tls_version": self.min_tls_version,
            "allowed_ciphers": self.allowed_ciphers,
            "hsts_max_age": self.hsts_max_age,
            "require_hsts": self.require_hsts,
            "cert_expiry_threshold": self.cert_expiry_threshold,
            "test_endpoints": self.test_endpoints,
            "last_validation": None
        }


# Global TLS validator instance
tls_validator = TLSValidator()


async def validate_tls_configuration(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Validate TLS configuration"""
    return await tls_validator.validate_tls_configuration(hostname, port)


async def validate_all_tls_endpoints() -> List[Dict[str, Any]]:
    """Validate TLS configuration for all endpoints"""
    return await tls_validator.validate_all_endpoints()


def get_tls_recommendations(validation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get TLS security recommendations"""
    return tls_validator.get_tls_recommendations(validation_results)


def get_tls_validation_summary() -> Dict[str, Any]:
    """Get TLS validation summary"""
    return tls_validator.get_validation_summary()
