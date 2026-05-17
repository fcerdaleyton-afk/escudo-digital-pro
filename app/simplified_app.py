#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Simplified Application
Consolidated application with reduced complexity and improved maintainability
"""

import os
import sys
import asyncio
import logging
from typing import Dict, List, Optional, Any

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.simplified_core import simplified_core, initialize_core_system, cleanup_core_system
from api.simplified_api import simplified_api, handle_api_request, initialize_simplified_api, cleanup_simplified_api

# Configure application logging
app_logger = logging.getLogger('simplified_app')


class SimplifiedApplication:
    """Simplified application wrapper"""
    
    def __init__(self):
        self.core = simplified_core
        self.api = simplified_api
        self.is_running = False
        
    async def start(self):
        """Start application"""
        try:
            app_logger.info("Starting simplified application")
            
            # Initialize core
            await initialize_core_system()
            
            # Initialize API
            await initialize_simplified_api()
            
            self.is_running = True
            app_logger.info("Simplified application started successfully")
            
        except Exception as e:
            app_logger.error(f"Error starting application: {e}")
            raise
    
    async def stop(self):
        """Stop application"""
        try:
            app_logger.info("Stopping simplified application")
            
            self.is_running = False
            
            # Cleanup API
            await cleanup_simplified_api()
            
            # Cleanup core
            await cleanup_core_system()
            
            app_logger.info("Simplified application stopped successfully")
            
        except Exception as e:
            app_logger.error(f"Error stopping application: {e}")
    
    async def handle_request(self, method: str, path: str, data: Dict[str, Any] = None, 
                           headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Handle application request"""
        return await handle_api_request(method, path, data, headers)
    
    def get_status(self) -> Dict[str, Any]:
        """Get application status"""
        return {
            'is_running': self.is_running,
            'core': self.core.get_status(),
            'api': {
                'routes': len(self.api.routes),
                'middleware': len(self.api.middleware)
            }
        }


# Global application instance
simplified_app = SimplifiedApplication()


# Main application functions
async def start_application() -> str:
    """Start application"""
    try:
        await simplified_app.start()
        return "Application started successfully"
    except Exception as e:
        return f"Error starting application: {e}"


async def stop_application() -> str:
    """Stop application"""
    try:
        await simplified_app.stop()
        return "Application stopped successfully"
    except Exception as e:
        return f"Error stopping application: {e}"


async def handle_request(method: str, path: str, data: Dict[str, Any] = None, 
                       headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Handle request"""
    return await simplified_app.handle_request(method, path, data, headers)


def get_application_status() -> Dict[str, Any]:
    """Get application status"""
    return simplified_app.get_status()


# Main entry point
if __name__ == "__main__":
    async def main():
        """Main function"""
        try:
            await start_application()
            
            # Keep application running
            while simplified_app.is_running:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            await stop_application()
        except Exception as e:
            print(f"Application error: {e}")
            await stop_application()
    
    asyncio.run(main())
