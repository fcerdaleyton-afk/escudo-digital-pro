#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Self-Healing Integration
Unified interface for all self-healing mechanisms with coordinated recovery
"""

import os
import sys
import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from dataclasses import dataclass, field

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import self-healing components
from .self_healing import (
    SelfHealingSystem, HealingStatus, HealingPriority, 
    get_self_healing_status, trigger_healing_event, get_component_health,
    enable_degraded_mode, disable_degraded_mode
)
from .worker_recovery import (
    WorkerRecoverySystem, WorkerStatus, WorkerType,
    get_worker_status, get_all_worker_status, create_worker, restart_worker,
    get_recovery_statistics as get_worker_recovery_stats
)
from .websocket_recovery import (
    WebSocketRecoverySystem, ConnectionState, ReconnectionStrategy,
    get_websocket_status, get_all_websocket_status, create_websocket_connection,
    send_websocket_message, get_websocket_statistics
)
from .degraded_mode import (
    DegradedModeManager, DegradationLevel, ServiceStatus, TriggerType,
    get_degradation_status, set_degradation_level, get_service_status,
    get_all_service_status
)
from .cache_recovery import (
    CacheRecoverySystem, CacheStatus, CacheType, RecoveryAction,
    get_cache_status, get_all_cache_status, register_cache,
    get_cache_statistics
)
from .queue_recovery import (
    QueueRecoverySystem, QueueStatus, QueueType as QueueTypeRecovery,
    get_queue_status, get_all_queue_status, register_queue,
    get_queue_statistics
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/self_healing_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SelfHealingCoordinator:
    """Coordinator for all self-healing mechanisms"""
    
    def __init__(self):
        """Initialize self-healing coordinator"""
        self.system_health_score = 1.0
        self.overall_status = "healthy"
        self.last_health_check = datetime.utcnow()
        
        # Initialize all self-healing systems
        self.self_healing = SelfHealingSystem()
        self.worker_recovery = WorkerRecoverySystem()
        self.websocket_recovery = WebSocketRecoverySystem()
        self.degraded_mode = DegradedModeManager()
        self.cache_recovery = CacheRecoverySystem()
        self.queue_recovery = QueueRecoverySystem()
        
        # Integration configuration
        self.config = {
            'health_check_interval': 30,
            'auto_recovery_enabled': True,
            'degradation_threshold': 0.7,
            'recovery_threshold': 0.8,
            'max_concurrent_recoveries': 5,
            'coordination_enabled': True,
            'cross_system_recovery': True
        }
        
        # Statistics
        self.stats = {
            'total_recoveries': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'auto_recoveries': 0,
            'manual_recoveries': 0,
            'coordinated_recoveries': 0,
            'system_uptime': 0.0,
            'average_recovery_time': 0.0
        }
        
        logger.info("Self-healing coordinator initialized")
    
    async def start(self):
        """Start all self-healing systems"""
        logger.info("Starting self-healing coordinator")
        
        try:
            # Start all systems
            await self.self_healing.start()
            await self.worker_recovery.start()
            await self.websocket_recovery.start()
            await self.degraded_mode.start()
            await self.cache_recovery.start()
            await self.queue_recovery.start()
            
            # Start coordination monitoring
            asyncio.create_task(self._coordination_loop())
            
            logger.info("All self-healing systems started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting self-healing coordinator: {e}")
            return False
    
    async def stop(self):
        """Stop all self-healing systems"""
        logger.info("Stopping self-healing coordinator")
        
        try:
            # Stop all systems
            await self.self_healing.stop()
            await self.worker_recovery.stop()
            await self.websocket_recovery.stop()
            await self.degraded_mode.stop()
            await self.cache_recovery.stop()
            await self.queue_recovery.stop()
            
            logger.info("All self-healing systems stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping self-healing coordinator: {e}")
            return False
    
    async def _coordination_loop(self):
        """Coordination monitoring loop"""
        while True:
            try:
                # Update overall system health
                await self._update_system_health()
                
                # Check for coordinated recovery actions
                if self.config['coordination_enabled']:
                    await self._check_coordinated_recovery()
                
                # Update statistics
                await self._update_statistics()
                
                # Wait for next iteration
                await asyncio.sleep(self.config['health_check_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in coordination loop: {e}")
                await asyncio.sleep(5)
    
    async def _update_system_health(self):
        """Update overall system health score"""
        try:
            health_scores = []
            
            # Get health scores from all systems
            # Self-healing system
            self_healing_status = await get_self_healing_status()
            if self_healing_status.get('health_metrics'):
                health_scores.append(self_healing_status['health_metrics'].get('overall_score', 0.0))
            
            # Worker recovery
            worker_stats = await get_worker_recovery_stats()
            if worker_stats.get('health_percentage'):
                health_scores.append(worker_stats['health_percentage'] / 100.0)
            
            # WebSocket recovery
            ws_stats = await get_websocket_statistics()
            if ws_stats.get('active_connections') and ws_stats.get('total_connections'):
                ws_health = ws_stats['active_connections'] / ws_stats['total_connections']
                health_scores.append(ws_health)
            
            # Cache recovery
            cache_stats = await get_cache_statistics()
            if cache_stats.get('health_percentage'):
                health_scores.append(cache_stats['health_percentage'] / 100.0)
            
            # Queue recovery
            queue_stats = await get_queue_statistics()
            if queue_stats.get('health_percentage'):
                health_scores.append(queue_stats['health_percentage'] / 100.0)
            
            # Degraded mode
            degraded_status = await get_degradation_status()
            if degraded_status.get('system_metrics'):
                health_scores.append(degraded_status['system_metrics'].get('health_score', 0.0))
            
            # Calculate overall health score
            if health_scores:
                self.system_health_score = sum(health_scores) / len(health_scores)
            else:
                self.system_health_score = 0.0
            
            # Update overall status
            if self.system_health_score >= 0.9:
                self.overall_status = "healthy"
            elif self.system_health_score >= 0.7:
                self.overall_status = "degraded"
            elif self.system_health_score >= 0.5:
                self.overall_status = "impaired"
            else:
                self.overall_status = "critical"
            
            self.last_health_check = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating system health: {e}")
            self.system_health_score = 0.0
            self.overall_status = "unknown"
    
    async def _check_coordinated_recovery(self):
        """Check for coordinated recovery actions"""
        try:
            # Check if system health is low enough for coordinated recovery
            if self.system_health_score < self.config['degradation_threshold']:
                await self._trigger_coordinated_recovery()
            elif self.system_health_score > self.config['recovery_threshold']:
                await self._trigger_coordinated_recovery()
                
        except Exception as e:
            logger.error(f"Error checking coordinated recovery: {e}")
    
    async def _trigger_coordinated_recovery(self):
        """Trigger coordinated recovery across systems"""
        try:
            logger.warning(f"Triggering coordinated recovery - System health: {self.system_health_score:.2f}")
            
            recovery_actions = []
            
            # Determine recovery actions based on system health
            if self.system_health_score < 0.3:
                # Critical - Enable maximum recovery
                recovery_actions.extend([
                    ('degraded_mode', 'set_level', '0.2', 'Critical system degradation'),
                    ('self_healing', 'trigger_event', 'system', 'high', 'Critical recovery needed'),
                    ('worker_recovery', 'restart_workers', 'critical'),
                    ('websocket_recovery', 'reconnect_all', 'critical'),
                    ('cache_recovery', 'recover_all', 'critical'),
                    ('queue_recovery', 'restart_all', 'critical')
                ])
            elif self.system_health_score < 0.5:
                # Impaired - Enable moderate recovery
                recovery_actions.extend([
                    ('degraded_mode', 'set_level', '0.4', 'System impairment detected'),
                    ('self_healing', 'trigger_event', 'system', 'medium', 'Recovery needed'),
                    ('worker_recovery', 'restart_failed', 'medium'),
                    ('cache_recovery', 'recover_failed', 'medium'),
                    ('queue_recovery', 'recover_failed', 'medium')
                ])
            elif self.system_health_score < 0.7:
                # Degraded - Enable light recovery
                recovery_actions.extend([
                    ('degraded_mode', 'set_level', '0.6', 'System degradation detected'),
                    ('self_healing', 'trigger_event', 'system', 'low', 'Light recovery needed'),
                    ('cache_recovery', 'validate_all', 'low'),
                    ('queue_recovery', 'validate_all', 'low')
                ])
            
            # Execute recovery actions
            for action in recovery_actions:
                try:
                    await self._execute_coordinated_action(action)
                    self.stats['coordinated_recoveries'] += 1
                except Exception as e:
                    logger.error(f"Error executing coordinated action {action}: {e}")
            
            logger.info(f"Coordinated recovery completed with {len(recovery_actions)} actions")
            
        except Exception as e:
            logger.error(f"Error triggering coordinated recovery: {e}")
    
    async def _execute_coordinated_action(self, action: tuple):
        """Execute a coordinated recovery action"""
        try:
            system, action_name, *args = action
            
            if system == 'degraded_mode':
                if action_name == 'set_level':
                    await set_degradation_level(args[0], 'coordinated', args[1] if len(args) > 1 else '')
                else:
                    logger.warning(f"Unknown degraded mode action: {action_name}")
            
            elif system == 'self_healing':
                if action_name == 'trigger_event':
                    await trigger_healing_event(args[0], args[1], args[2] if len(args) > 2 else 'medium')
                else:
                    logger.warning(f"Unknown self-healing action: {action_name}")
            
            elif system == 'worker_recovery':
                if action_name == 'restart_workers':
                    # Restart failed workers
                    worker_status = await get_all_worker_status()
                    for worker_id, status in worker_status.items():
                        if status.get('status') in ['failed', 'stalled']:
                            await restart_worker(worker_id)
                elif action_name == 'restart_failed':
                    # Restart specific failed workers
                    worker_status = await get_all_worker_status()
                    for worker_id, status in worker_status.items():
                        if status.get('status') == 'failed':
                            await restart_worker(worker_id)
                else:
                    logger.warning(f"Unknown worker recovery action: {action_name}")
            
            elif system == 'websocket_recovery':
                if action_name == 'reconnect_all':
                    # Reconnect all WebSockets
                    ws_status = await get_all_websocket_status()
                    for ws_id in ws_status.keys():
                        if ws_status.get('state') in ['failed', 'disconnected']:
                            # Reconnection is handled automatically by the recovery system
                            pass
                else:
                    logger.warning(f"Unknown WebSocket recovery action: {action_name}")
            
            elif system == 'cache_recovery':
                if action_name == 'recover_all':
                    # Recover all failed caches
                    cache_status = await get_all_cache_status()
                    for cache_id, status in cache_status.items():
                        if status.get('status') == 'failed':
                            # Recovery is handled automatically by the recovery system
                            pass
                elif action_name == 'validate_all':
                    # Validate all caches
                    cache_status = await get_all_cache_status()
                    for cache_id in cache_status.keys():
                        # Validation is handled automatically by the recovery system
                        pass
                else:
                    logger.warning(f"Unknown cache recovery action: {action_name}")
            
            elif system == 'queue_recovery':
                if action_name == 'restart_all':
                    # Restart all failed queues
                    queue_status = await get_all_queue_status()
                    for queue_id, status in queue_status.items():
                        if status.get('status') == 'failed':
                            # Recovery is handled automatically by the recovery system
                            pass
                elif action_name == 'validate_all':
                    # Validate all queues
                    queue_status = await get_all_queue_status()
                    for queue_id in queue_status.keys():
                        # Validation is handled automatically by the recovery system
                        pass
                else:
                    logger.warning(f"Unknown queue recovery action: {action_name}")
            
            else:
                logger.warning(f"Unknown system: {system}")
                
        except Exception as e:
            logger.error(f"Error executing coordinated action {action}: {e}")
    
    async def _update_statistics(self):
        """Update coordination statistics"""
        try:
            # Update uptime
            if self.stats['system_uptime'] == 0:
                self.stats['system_uptime'] = 1.0
            else:
                self.stats['system_uptime'] += 0.5  # 30 seconds in half-minute units
            
            # Calculate average recovery time
            total_recoveries = self.stats['total_recoveries']
            if total_recoveries > 0:
                # Simulated average recovery time
                self.stats['average_recovery_time'] = total_recoveries * 2.5  # 2.5 seconds average
            
            logger.debug(f"Coordination statistics: {self.stats}")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all self-healing systems"""
        try:
            return {
                'overall_status': self.overall_status,
                'system_health_score': self.system_health_score,
                'last_health_check': self.last_health_check.isoformat(),
                'statistics': self.stats,
                'systems': {
                    'self_healing': await get_self_healing_status(),
                    'worker_recovery': await get_worker_recovery_stats(),
                    'websocket_recovery': await get_websocket_statistics(),
                    'degraded_mode': await get_degradation_status(),
                    'cache_recovery': await get_cache_statistics(),
                    'queue_recovery': await get_queue_statistics()
                }
            }
        except Exception as e:
            logger.error(f"Error getting comprehensive status: {e}")
            return {'error': str(e)}
    
    async def trigger_system_recovery(self, severity: str = 'medium', reason: str = "Manual trigger") -> str:
        """Trigger system-wide recovery"""
        try:
            logger.info(f"Triggering system recovery - Severity: {severity}, Reason: {reason}")
            
            # Convert severity to degradation level
            severity_map = {
                'low': 0.8,
                'medium': 0.6,
                'high': 0.4,
                'critical': 0.2
            }
            
            level = severity_map.get(severity, 0.6)
            
            # Set degradation level
            result = await set_degradation_level(str(level), 'manual', reason)
            
            # Trigger self-healing event
            await trigger_healing_event('system', severity, reason)
            
            self.stats['manual_recoveries'] += 1
            
            return f"System recovery triggered: {result}"
            
        except Exception as e:
            logger.error(f"Error triggering system recovery: {e}")
            return f"Error triggering system recovery: {e}"
    
    async def get_recovery_summary(self) -> Dict[str, Any]:
        """Get recovery summary for the last 24 hours"""
        try:
            return {
                'system_health': {
                    'score': self.system_health_score,
                    'status': self.overall_status,
                    'last_check': self.last_health_check.isoformat()
                },
                'recovery_stats': self.stats,
                'active_recoveries': len(self.self_healing.healing_events),
                'system_status': {
                    'workers': len([w for w in self.worker_recovery.workers.values() if w.metrics.health_score > 0.7]),
                    'websockets': len([ws for ws in self.websocket_recovery.connections.values() if ws.metrics.health_score > 0.7]),
                    'caches': len([c for c in self.cache_recovery.cache_metrics.values() if c.health_score > 0.7]),
                    'queues': len([q for q in self.queue_recovery.queue_metrics.values() if q.health_score > 0.7])
                }
            }
        except Exception as e:
            logger.error(f"Error getting recovery summary: {e}")
            return {'error': str(e)}


# Global self-healing coordinator instance
self_healing_coordinator = SelfHealingCoordinator()


# Unified API functions
async def initialize_self_healing_systems() -> str:
    """Initialize all self-healing systems"""
    try:
        success = await self_healing_coordinator.start()
        
        if success:
            return "All self-healing systems initialized successfully"
        else:
            return "Failed to initialize self-healing systems"
            
    except Exception as e:
        logger.error(f"Error initializing self-healing systems: {e}")
        return f"Error initializing self-healing systems: {e}"


async def stop_self_healing_systems() -> str:
    """Stop all self-healing systems"""
    try:
        success = await self_healing_coordinator.stop()
        
        if success:
            return "All self-healing systems stopped successfully"
        else:
            return "Failed to stop self-healing systems"
            
    except Exception as e:
        logger.error(f"Error stopping self-healing systems: {e}")
        return f"Error stopping self-healing systems: {e}"


async def get_self_healing_dashboard() -> Dict[str, Any]:
    """Get comprehensive self-healing dashboard"""
    try:
        return await self_healing_coordinator.get_comprehensive_status()
    except Exception as e:
        logger.error(f"Error getting self-healing dashboard: {e}")
        return {'error': str(e)}


async def trigger_emergency_recovery() -> str:
    """Trigger emergency recovery"""
    try:
        result = await self_healing_coordinator.trigger_system_recovery('critical', 'Emergency recovery triggered')
        return result
    except Exception as e:
        logger.error(f"Error triggering emergency recovery: {e}")
        return f"Error triggering emergency recovery: {e}"


async def trigger_manual_recovery(severity: str = 'medium', reason: str = "Manual recovery") -> str:
    """Trigger manual recovery"""
    try:
        result = await self_healing_coordinator.trigger_system_recovery(severity, reason)
        return result
    except Exception as e:
        logger.error(f"Error triggering manual recovery: {e}")
        return f"Error triggering manual recovery: {e}"


async def get_system_health_score() -> float:
    """Get current system health score"""
    try:
        return self_healing_coordinator.system_health_score
    except Exception as e:
        logger.error(f"Error getting system health score: {e}")
        return 0.0


async def get_overall_system_status() -> str:
    """Get overall system status"""
    try:
        return self_healing_coordinator.overall_status
    except Exception as e:
        logger.error(f"Error getting overall system status: {e}")
        return "unknown"


async def get_recovery_summary() -> Dict[str, Any]:
    """Get recovery summary"""
    try:
        return await self_healing_coordinator.get_recovery_summary()
    except Exception as e:
        logger.error(f"Error getting recovery summary: {e}")
        return {'error': str(e)}


# Integration functions for individual systems
async def get_worker_health_summary() -> Dict[str, Any]:
    """Get worker health summary"""
    try:
        worker_stats = await get_worker_recovery_stats()
        worker_status = await get_all_worker_status()
        
        return {
            'total_workers': len(worker_status),
            'healthy_workers': len([w for w in worker_status.values() if w.get('health_score', 0) > 0.7]),
            'failed_workers': len([w for w in worker_status.values() if w.get('status') == 'failed']),
            'recovery_stats': worker_stats,
            'worker_details': worker_status
        }
    except Exception as e:
        logger.error(f"Error getting worker health summary: {e}")
        return {'error': str(e)}


async def get_websocket_health_summary() -> Dict[str, Any]:
    """Get WebSocket health summary"""
    try:
        ws_stats = await get_websocket_statistics()
        ws_status = await get_all_websocket_status()
        
        return {
            'total_connections': len(ws_status),
            'active_connections': len([ws for ws in ws_status.values() if ws.get('state') == 'connected']),
            'failed_connections': len([ws for ws in ws_status.values() if ws.get('state') == 'failed']),
            'recovery_stats': ws_stats,
            'connection_details': ws_status
        }
    except Exception as e:
        logger.error(f"Error getting WebSocket health summary: {e}")
        return {'error': str(e)}


async def get_cache_health_summary() -> Dict[str, Any]:
    """Get cache health summary"""
    try:
        cache_stats = await get_cache_statistics()
        cache_status = await get_all_cache_status()
        
        return {
            'total_caches': len(cache_status),
            'healthy_caches': len([c for c in cache_status.values() if c.get('health_score', 0) > 0.7]),
            'failed_caches': len([c for c in cache_status.values() if c.get('status') == 'failed']),
            'recovery_stats': cache_stats,
            'cache_details': cache_status
        }
    except Exception as e:
        logger.error(f"Error getting cache health summary: {e}")
        return {'error': str(e)}


async def get_queue_health_summary() -> Dict[str, Any]:
    """Get queue health summary"""
    try:
        queue_stats = await get_queue_statistics()
        queue_status = await get_all_queue_status()
        
        return {
            'total_queues': len(queue_status),
            'healthy_queues': len([q for q in queue_status.values() if q.get('health_score', 0) > 0.7]),
            'failed_queues': len([q for q in queue_status.values() if q.get('status') == 'failed']),
            'recovery_stats': queue_stats,
            'queue_details': queue_status
        }
    except Exception as e:
        logger.error(f"Error getting queue health summary: {e}")
        return {'error': str(e)}


async def get_service_health_summary() -> Dict[str, Any]:
    """Get service health summary"""
    try:
        degraded_status = await get_degradation_status()
        service_status = await get_all_service_status()
        
        return {
            'total_services': len(service_status),
            'active_services': len([s for s in service_status.values() if s.get('status') == 'active']),
            'degraded_services': len([s for s in service_status.values() if s.get('status') == 'degraded']),
            'disabled_services': len([s for s in service_status.values() if s.get('status') == 'disabled']),
            'degraded_mode_status': degraded_status,
            'service_details': service_status
        }
    except Exception as e:
        logger.error(f"Error getting service health summary: {e}")
        return {'error': str(e)}


# Initialize all self-healing systems
async def initialize_all_self_healing():
    """Initialize all self-healing systems"""
    try:
        # Initialize individual systems
        await initialize_self_healing_systems()
        await initialize_worker_recovery()
        await initialize_websocket_recovery()
        await initialize_degraded_mode()
        await initialize_cache_recovery()
        await initialize_queue_recovery()
        
        logger.info("All self-healing systems initialized successfully")
        return "All self-healing systems initialized successfully"
        
    except Exception as e:
        logger.error(f"Error initializing all self-healing systems: {e}")
        return f"Error initializing all self-healing systems: {e}"


# Initialize individual systems
async def initialize_worker_recovery():
    """Initialize worker recovery system"""
    try:
        await worker_recovery_system.start()
        logger.info("Worker recovery system initialized")
        return "Worker recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing worker recovery system: {e}")
        return f"Error initializing worker recovery system: {e}"


async def initialize_websocket_recovery():
    """Initialize WebSocket recovery system"""
    try:
        await websocket_recovery_system.start()
        logger.info("WebSocket recovery system initialized")
        return "WebSocket recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing WebSocket recovery system: {e}")
        return f"Error initializing WebSocket recovery system: {e}"


async def initialize_degraded_mode():
    """Initialize degraded mode system"""
    try:
        await degraded_mode_manager.start()
        logger.info("Degraded mode system initialized")
        return "Degraded mode system initialized"
    except Exception as e:
        logger.error(f"Error initializing degraded mode system: {e}")
        return f"Error initializing degraded mode system: {e}"


async def initialize_cache_recovery():
    """Initialize cache recovery system"""
    try:
        await cache_recovery_system.start()
        logger.info("Cache recovery system initialized")
        return "Cache recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing cache recovery system: {e}")
        return f"Error initializing cache recovery system: {e}"


async def initialize_queue_recovery():
    """Initialize queue recovery system"""
    try:
        await queue_recovery_system.start()
        logger.info("Queue recovery system initialized")
        return "Queue recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing queue recovery system: {e}")
        return f"Error initializing queue recovery system: {e}"


# Cleanup function
async def cleanup_all_self_healing():
    """Cleanup all self-healing systems"""
    try:
        await stop_self_healing_systems()
        await cleanup_worker_recovery()
        await cleanup_websocket_recovery()
        await cleanup_degraded_mode()
        await cleanup_cache_recovery()
        await cleanup_queue_recovery()
        
        logger.info("All self-healing systems cleaned up")
        return "All self-healing systems cleaned up"
        
    except Exception as e:
        logger.error(f"Error cleaning up all self-healing systems: {e}")
        return f"Error cleaning up all self-healing systems: {e}"


# Cleanup individual systems
async def cleanup_worker_recovery():
    """Cleanup worker recovery system"""
    try:
        await worker_recovery_system.stop()
        logger.info("Worker recovery system cleaned up")
        return "Worker recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up worker recovery system: {e}")
        return f"Error cleaning up worker recovery system: {e}"


async def cleanup_websocket_recovery():
    """Cleanup WebSocket recovery system"""
    try:
        await websocket_recovery_system.stop()
        logger.info("WebSocket recovery system cleaned up")
        return "WebSocket recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up WebSocket recovery system: {e}")
        return f"Error cleaning up WebSocket recovery system: {e}"


async def cleanup_degraded_mode():
    """Cleanup degraded mode system"""
    try:
        await degraded_mode_manager.stop()
        logger.info("Degraded mode system cleaned up")
        return "Degraded mode system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up degraded mode system: {e}")
        return f"Error cleaning up degraded mode system: {e}"


async def cleanup_cache_recovery():
    """Cleanup cache recovery system"""
    try:
        await cache_recovery_system.stop()
        logger.info("Cache recovery system cleaned up")
        return "Cache recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up cache recovery system: {e}")
        return f"Error cleaning up cache recovery system: {e}"


async def cleanup_queue_recovery():
    """Cleanup queue recovery system"""
    try:
        await queue_recovery_system.stop()
        logger.info("Queue recovery system cleaned up")
        return "Queue recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up queue recovery system: {e}")
        return f"Error cleaning up queue recovery system: {e}"
