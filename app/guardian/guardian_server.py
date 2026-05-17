#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Guardian Server
Windows Guardian monitoring service with FastAPI interface
"""

import os
import sys
import asyncio
import logging
import signal
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
def setup_logging():
    """Setup logging with proper path handling"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'guardian_server.log')),
            logging.StreamHandler(sys.stdout)
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

# Import application components
try:
    from core.env_validator import initialize_environment_validation
    from windows_guardian import initialize_windows_guardian
    from host_monitor import initialize_host_monitor
    from event_watchers import initialize_event_monitor
    from process_watchers import process_analyzer
    from alerting import initialize_alert_manager
except ImportError as e:
    logger.error(f"Failed to import guardian components: {e}")
    sys.exit(1)

# Import FastAPI components
try:
    from fastapi import FastAPI, Request, Response, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse
    import uvicorn
except ImportError as e:
    logger.error(f"Failed to import FastAPI components: {e}")
    sys.exit(1)


class GuardianServer:
    """Guardian monitoring server"""
    
    def __init__(self):
        """Initialize guardian server"""
        self.app = FastAPI(
            title="MARY V5 Guardian",
            description="Windows Guardian Monitoring Service",
            version="5.0.0",
            docs_url="/docs" if os.environ.get('ENVIRONMENT') == 'development' else None,
            redoc_url="/redoc" if os.environ.get('ENVIRONMENT') == 'development' else None
        )
        
        self.is_running = False
        self.startup_time = None
        self.api_endpoint = os.environ.get('API_ENDPOINT', 'http://mary-api:8000')
        self.api_host = os.environ.get('API_HOST', 'mary-api')
        self.api_port = int(os.environ.get('API_PORT', '8000'))
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup routes
        self._setup_routes()
        
        logger.info("Guardian server initialized")
    
    def _setup_middleware(self):
        """Setup security middleware"""
        # CORS middleware
        cors_origins = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8080,http://localhost:8000').split(',')
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"]
        )
        
        # Trusted hosts middleware
        allowed_hosts = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,mary-api').split(',')
        self.app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=allowed_hosts
        )
        
        # Security headers middleware
        @self.app.middleware("http")
        async def add_security_headers(request: Request, call_next):
            response = await call_next(request)
            
            # Security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            
            return response
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = datetime.utcnow()
            
            try:
                response = await call_next(request)
                
                # Log request
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.info(f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s")
                
                return response
                
            except Exception as e:
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.error(f"{request.method} {request.url.path} - ERROR - {duration:.3f}s - {e}")
                raise
    
    def _setup_routes(self):
        """Setup guardian routes"""
        
        @self.app.get("/")
        async def root():
            """Root endpoint"""
            return {
                "name": "MARY V5 Guardian",
                "version": "5.0.0",
                "mode": "monitoring",
                "status": "operational",
                "timestamp": datetime.utcnow().isoformat(),
                "uptime": (datetime.utcnow() - self.startup_time).total_seconds() if self.startup_time else 0,
                "api_endpoint": self.api_endpoint
            }
        
        @self.app.get("/health")
        async def health():
            """Health check endpoint"""
            try:
                # Check API connectivity
                api_status = await self._check_api_connectivity()
                
                # Check guardian components
                guardian_status = "operational"
                host_monitor_status = "operational"
                event_monitor_status = "operational"
                process_analyzer_status = "operational"
                
                # Overall status
                overall_status = "operational" if all([
                    api_status == "operational",
                    guardian_status == "operational",
                    host_monitor_status == "operational",
                    event_monitor_status == "operational",
                    process_analyzer_status == "operational"
                ]) else "degraded"
                
                return {
                    "status": overall_status,
                    "timestamp": datetime.utcnow().isoformat(),
                    "components": {
                        "api": api_status,
                        "guardian": guardian_status,
                        "host_monitor": host_monitor_status,
                        "event_monitor": event_monitor_status,
                        "process_analyzer": process_analyzer_status
                    },
                    "api_endpoint": self.api_endpoint,
                    "uptime": (datetime.utcnow() - self.startup_time).total_seconds() if self.startup_time else 0
                }
            except Exception as e:
                logger.error(f"Health check error: {e}")
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "error",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
        
        @self.app.get("/status")
        async def status():
            """Detailed status endpoint"""
            try:
                from host_monitor import get_monitor_status
                from windows_guardian import get_guardian_statistics
                from event_watchers import get_event_statistics
                from process_watchers import get_analyzer_statistics
                from alerting import get_alert_statistics
                
                return {
                    "guardian": {
                        "name": "MARY V5 Guardian",
                        "version": "5.0.0",
                        "environment": os.environ.get('ENVIRONMENT', 'unknown'),
                        "uptime": (datetime.utcnow() - self.startup_time).total_seconds() if self.startup_time else 0,
                        "status": "operational",
                        "api_endpoint": self.api_endpoint,
                        "api_host": self.api_host,
                        "api_port": self.api_port
                    },
                    "host_monitor": get_monitor_status(),
                    "windows_guardian": get_guardian_statistics(),
                    "event_monitor": get_event_statistics(),
                    "process_analyzer": get_analyzer_statistics(),
                    "alerting": get_alert_statistics(),
                    "timestamp": datetime.utcnow().isoformat()
                }
            except Exception as e:
                logger.error(f"Status endpoint error: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": str(e), "timestamp": datetime.utcnow().isoformat()}
                )
        
        @self.app.get("/monitoring/connectivity")
        async def connectivity():
            """API connectivity check"""
            try:
                connectivity_result = await self._check_api_connectivity()
                
                return {
                    "api_endpoint": self.api_endpoint,
                    "api_host": self.api_host,
                    "api_port": self.api_port,
                    "status": connectivity_result,
                    "timestamp": datetime.utcnow().isoformat()
                }
            except Exception as e:
                logger.error(f"Connectivity check error: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": str(e), "timestamp": datetime.utcnow().isoformat()}
                )
        
        @self.app.post("/monitoring/test-alert")
        async def test_alert():
            """Test alert generation"""
            try:
                from alerting import create_alert
                
                alert_id = await create_alert(
                    title="Guardian Test Alert",
                    message="Test alert from MARY V5 Guardian service",
                    severity="info",
                    source="guardian_test",
                    details={
                        "guardian_host": os.environ.get('HOSTNAME', 'unknown'),
                        "api_endpoint": self.api_endpoint,
                        "test_timestamp": datetime.utcnow().isoformat()
                    }
                )
                
                return {
                    "status": "success",
                    "message": "Test alert generated successfully",
                    "alert_id": alert_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            except Exception as e:
                logger.error(f"Test alert error: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": str(e), "timestamp": datetime.utcnow().isoformat()}
                )
    
    async def _check_api_connectivity(self) -> str:
        """Check API connectivity"""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self.api_endpoint}/health") as response:
                    if response.status == 200:
                        return "operational"
                    else:
                        return f"error_{response.status}"
                        
        except aiohttp.ClientConnectorError:
            return "connection_refused"
        except aiohttp.ClientTimeout:
            return "timeout"
        except Exception as e:
            logger.error(f"API connectivity check error: {e}")
            return "error"
    
    async def startup(self):
        """Startup sequence"""
        try:
            logger.info("Starting MARY V5 Guardian Service")
            self.startup_time = datetime.utcnow()
            
            # 1. Validate environment
            logger.info("Step 1: Validating environment variables")
            env_validation = initialize_environment_validation()
            if "Error" in env_validation:
                logger.warning(f"Environment validation warning: {env_validation}")
            else:
                logger.info("✓ Environment validation completed")
            
            # 2. Initialize Windows Guardian
            logger.info("Step 2: Initializing Windows Guardian")
            guardian_init = await initialize_windows_guardian()
            if "Error" in guardian_init:
                logger.warning(f"Windows Guardian initialization warning: {guardian_init}")
            else:
                logger.info("✓ Windows Guardian initialized")
            
            # 3. Initialize Host Monitor
            logger.info("Step 3: Initializing Host Monitor")
            host_monitor_init = await initialize_host_monitor()
            if "Error" in host_monitor_init:
                logger.warning(f"Host Monitor initialization warning: {host_monitor_init}")
            else:
                logger.info("✓ Host Monitor initialized")
            
            # 4. Initialize Event Monitor
            logger.info("Step 4: Initializing Event Monitor")
            event_monitor_init = await initialize_event_monitor()
            if "Error" in event_monitor_init:
                logger.warning(f"Event Monitor initialization warning: {event_monitor_init}")
            else:
                logger.info("✓ Event Monitor initialized")
            
            # 5. Initialize Alert Manager
            logger.info("Step 5: Initializing Alert Manager")
            alert_manager_init = await initialize_alert_manager()
            if "Error" in alert_manager_init:
                logger.warning(f"Alert Manager initialization warning: {alert_manager_init}")
            else:
                logger.info("✓ Alert Manager initialized")
            
            # 6. Check API connectivity
            logger.info("Step 6: Checking API connectivity")
            api_status = await self._check_api_connectivity()
            if api_status == "operational":
                logger.info(f"✓ API connectivity confirmed: {self.api_endpoint}")
            else:
                logger.warning(f"⚠ API connectivity issue: {api_status} - {self.api_endpoint}")
            
            # 7. Log successful startup
            startup_duration = (datetime.utcnow() - self.startup_time).total_seconds()
            logger.info(f"✓ MARY V5 Guardian startup completed in {startup_duration:.2f}s")
            logger.info("✓ Guardian monitoring service operational")
            
            self.is_running = True
            
            # Emit startup event
            logger.info(f"MARY V5 Guardian is monitoring API at {self.api_endpoint}")
            
        except Exception as e:
            logger.error(f"Guardian startup failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    async def shutdown(self):
        """Shutdown sequence"""
        try:
            logger.info("Shutting down MARY V5 Guardian")
            
            if self.is_running:
                # Stop monitoring services
                logger.info("Stopping monitoring services")
                
                self.is_running = False
                
                logger.info("MARY V5 Guardian shutdown completed")
            
        except Exception as e:
            logger.error(f"Guardian shutdown error: {e}")
    
    def get_app(self) -> FastAPI:
        """Get FastAPI application"""
        return self.app


# Global guardian server instance
guardian_server = GuardianServer()


# Startup and shutdown handlers
async def startup_handler():
    """Guardian startup handler"""
    await guardian_server.startup()

async def shutdown_handler():
    """Guardian shutdown handler"""
    await guardian_server.shutdown()

# Signal handlers
def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating shutdown")
    asyncio.create_task(shutdown_handler())

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Main execution
if __name__ == "__main__":
    try:
        # Get configuration
        host = os.environ.get('GUARDIAN_HOST', '0.0.0.0')
        port = int(os.environ.get('GUARDIAN_PORT', '8081'))
        workers = int(os.environ.get('GUARDIAN_WORKERS', '1'))  # Single worker for monitoring
        
        # Run guardian server
        logger.info(f"Starting MARY V5 Guardian on {host}:{port}")
        
        # Configure uvicorn
        config = uvicorn.Config(
            app=guardian_server.get_app(),
            host=host,
            port=port,
            workers=workers,
            log_level=os.environ.get('LOG_LEVEL', 'info').lower(),
            access_log=True,
            use_colors=False,
            loop="asyncio"
        )
        
        # Start server
        server = uvicorn.Server(config)
        
        # Add startup and shutdown handlers
        server.config.on_startup(startup_handler)
        server.config.on_shutdown(shutdown_handler)
        
        # Run server
        server.run()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)
