"""
Enterprise Integration for Mary V5
Main integration point for all enterprise security components
"""

import os
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from app.core.dependencies import logger
from app.security.advanced_middleware import get_advanced_security_middleware
from app.detection.threat_engine import get_threat_detection_engine, start_threat_monitoring
from app.monitoring.dashboard import start_dashboard_services
from app.security.database_security import get_database_security_manager
from app.auth.zero_trust import get_zero_trust_summary
from app.services.performance_optimizer import initialize_performance_optimizer, shutdown_performance_optimizer
from app.detection.windows_hardening import start_windows_monitoring
from app.services.enterprise_features import get_enterprise_summary, run_enterprise_health_checks


class EnterpriseSecurityManager:
    """
    Main enterprise security manager that coordinates all security components
    """
    
    def __init__(self):
        self.enabled = os.getenv("ENTERPRISE_SECURITY_ENABLED", "true").lower() == "true"
        
        # Component managers
        self.components = {}
        
        # Background tasks
        self.background_tasks = []
        
        # Integration status
        self.integration_status = {
            "middleware": False,
            "threat_detection": False,
            "monitoring": False,
            "database_security": False,
            "zero_trust": False,
            "performance": False,
            "windows_hardening": False,
            "enterprise_features": False
        }
        
        logger.info("Enterprise security manager initialized", enabled=self.enabled)
    
    async def initialize(self, app=None):
        """Initialize all enterprise security components"""
        if not self.enabled:
            logger.info("Enterprise security is disabled")
            return
        
        logger.info("Initializing enterprise security components")
        
        try:
            # 1. Initialize advanced security middleware
            if app:
                middleware = get_advanced_security_middleware(app)
                self.components["middleware"] = middleware
                self.integration_status["middleware"] = True
                logger.info("Advanced security middleware initialized")
            
            # 2. Initialize threat detection engine
            threat_engine = get_threat_detection_engine()
            self.components["threat_engine"] = threat_engine
            self.integration_status["threat_detection"] = True
            
            # Start threat monitoring in background
            threat_task = asyncio.create_task(start_threat_monitoring())
            self.background_tasks.append(threat_task)
            logger.info("Threat detection engine initialized")
            
            # 3. Initialize real-time monitoring dashboard
            websocket_server, redis_task = await start_dashboard_services()
            self.components["dashboard"] = {
                "websocket_server": websocket_server,
                "redis_task": redis_task
            }
            self.integration_status["monitoring"] = True
            logger.info("Real-time monitoring dashboard initialized")
            
            # 4. Initialize database security
            db_security = get_database_security_manager()
            self.components["database_security"] = db_security
            self.integration_status["database_security"] = True
            logger.info("Database security initialized")
            
            # 5. Initialize zero-trust authentication
            zero_trust_summary = get_zero_trust_summary()
            self.components["zero_trust"] = zero_trust_summary
            self.integration_status["zero_trust"] = True
            logger.info("Zero-trust authentication initialized")
            
            # 6. Initialize performance optimization
            await initialize_performance_optimizer()
            self.components["performance"] = True
            self.integration_status["performance"] = True
            logger.info("Performance optimization initialized")
            
            # 7. Initialize Windows hardening (if on Windows)
            if os.name == 'nt':
                windows_task = asyncio.create_task(start_windows_monitoring())
                self.background_tasks.append(windows_task)
                self.integration_status["windows_hardening"] = True
                logger.info("Windows hardening initialized")
            else:
                self.integration_status["windows_hardening"] = False
                logger.info("Windows hardening skipped (not on Windows)")
            
            # 8. Initialize enterprise features
            enterprise_summary = get_enterprise_summary()
            self.components["enterprise_features"] = enterprise_summary
            self.integration_status["enterprise_features"] = True
            logger.info("Enterprise features initialized")
            
            # Log successful initialization
            logger.info("All enterprise security components initialized successfully")
            
            # Run initial health check
            await self._run_initial_health_check()
            
        except Exception as e:
            logger.error("Enterprise security initialization failed", error=str(e))
            raise
    
    async def _run_initial_health_check(self):
        """Run initial health check of all components"""
        try:
            health_status = await self.get_comprehensive_health_status()
            
            # Log component status
            for component, status in self.integration_status.items():
                if status:
                    logger.info(f"✓ {component} initialized successfully")
                else:
                    logger.warning(f"✗ {component} failed to initialize")
            
            # Log overall health
            overall_healthy = all(self.integration_status.values())
            if overall_healthy:
                logger.info("🛡️ Enterprise security system fully operational")
            else:
                logger.warning("⚠️ Enterprise security system partially operational")
        
        except Exception as e:
            logger.error("Initial health check failed", error=str(e))
    
    async def get_comprehensive_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of all components"""
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "operational",
            "components": {},
            "integration_status": self.integration_status.copy(),
            "background_tasks": len(self.background_tasks)
        }
        
        try:
            # Get enterprise health checks
            enterprise_health = await run_enterprise_health_checks()
            health_status["components"]["enterprise"] = enterprise_health
            
            # Get threat detection status
            if "threat_engine" in self.components:
                threat_summary = self.components["threat_engine"].get_threat_summary()
                health_status["components"]["threat_detection"] = {
                    "enabled": threat_summary["enabled"],
                    "total_threats": threat_summary["total_threats"],
                    "last_detection": threat_summary["last_detection"]
                }
            
            # Get database security status
            if "database_security" in self.components:
                db_security = self.components["database_security"].get_database_security_summary()
                health_status["components"]["database_security"] = db_security
            
            # Get performance status
            if "performance" in self.components:
                from app.services.performance_optimizer import get_performance_summary
                performance = get_performance_summary()
                health_status["components"]["performance"] = performance
            
            # Get enterprise features status
            if "enterprise_features" in self.components:
                enterprise = self.components["enterprise_features"]
                health_status["components"]["enterprise_features"] = enterprise
            
            # Determine overall status
            component_health = []
            for component_status in health_status["components"].values():
                if isinstance(component_status, dict):
                    if component_status.get("enabled", False):
                        component_health.append(True)
                    elif component_status.get("status") == "healthy":
                        component_health.append(True)
                    else:
                        component_health.append(False)
            
            if component_health and all(component_health):
                health_status["overall_status"] = "fully_operational"
            elif component_health and any(component_health):
                health_status["overall_status"] = "partially_operational"
            else:
                health_status["overall_status"] = "non_operational"
        
        except Exception as e:
            logger.error("Health status check failed", error=str(e))
            health_status["overall_status"] = "error"
            health_status["error"] = str(e)
        
        return health_status
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        dashboard_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "integration_status": self.integration_status.copy(),
            "components": {}
        }
        
        try:
            # Threat detection data
            if "threat_engine" in self.components:
                threat_summary = self.components["threat_engine"].get_threat_summary()
                recent_threats = self.components["threat_engine"].get_recent_threats(20)
                dashboard_data["components"]["threats"] = {
                    "summary": threat_summary,
                    "recent": recent_threats
                }
            
            # Database security data
            if "database_security" in self.components:
                db_security = self.components["database_security"].get_database_security_summary()
                dashboard_data["components"]["database"] = db_security
            
            # Zero-trust data
            if "zero_trust" in self.components:
                zero_trust = self.components["zero_trust"]
                dashboard_data["components"]["zero_trust"] = zero_trust
            
            # Performance data
            if "performance" in self.components:
                from app.services.performance_optimizer import get_performance_summary
                performance = get_performance_summary()
                dashboard_data["components"]["performance"] = performance
            
            # Enterprise features data
            if "enterprise_features" in self.components:
                enterprise = self.components["enterprise_features"]
                dashboard_data["components"]["enterprise"] = enterprise
        
        except Exception as e:
            logger.error("Dashboard data collection failed", error=str(e))
            dashboard_data["error"] = str(e)
        
        return dashboard_data
    
    async def shutdown(self):
        """Shutdown all enterprise security components"""
        if not self.enabled:
            return
        
        logger.info("Shutting down enterprise security components")
        
        try:
            # Cancel background tasks
            for task in self.background_tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            
            # Shutdown performance optimizer
            await shutdown_performance_optimizer()
            
            logger.info("Enterprise security components shutdown successfully")
        
        except Exception as e:
            logger.error("Enterprise security shutdown failed", error=str(e))
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics"""
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "integration_status": self.integration_status.copy(),
            "background_tasks_active": len(self.background_tasks)
        }
        
        try:
            # Component metrics
            if "threat_engine" in self.components:
                threat_metrics = self.components["threat_engine"].get_threat_summary()
                metrics["threat_detection"] = threat_metrics
            
            if "database_security" in self.components:
                db_metrics = self.components["database_security"].get_database_security_summary()
                metrics["database_security"] = db_metrics
            
            if "performance" in self.components:
                from app.services.performance_optimizer import get_performance_summary
                perf_metrics = get_performance_summary()
                metrics["performance"] = perf_metrics
            
            if "enterprise_features" in self.components:
                enterprise_metrics = self.components["enterprise_features"]
                metrics["enterprise"] = enterprise_metrics
        
        except Exception as e:
            logger.error("Security metrics collection failed", error=str(e))
            metrics["error"] = str(e)
        
        return metrics


# Global enterprise security manager
enterprise_security_manager = EnterpriseSecurityManager()


async def initialize_enterprise_security(app=None):
    """Initialize enterprise security system"""
    await enterprise_security_manager.initialize(app)


async def get_enterprise_health_status() -> Dict[str, Any]:
    """Get enterprise health status"""
    return await enterprise_security_manager.get_comprehensive_health_status()


def get_security_dashboard_data() -> Dict[str, Any]:
    """Get security dashboard data"""
    return enterprise_security_manager.get_security_dashboard_data()


def get_enterprise_security_metrics() -> Dict[str, Any]:
    """Get enterprise security metrics"""
    return enterprise_security_manager.get_security_metrics()


async def shutdown_enterprise_security():
    """Shutdown enterprise security system"""
    await enterprise_security_manager.shutdown()
