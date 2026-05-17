#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - WebSocket Reconnection System
Automatic WebSocket reconnection with fallback and resilience
"""

import os
import sys
import asyncio
import logging
import json
import time
import websockets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/websocket_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """WebSocket connection state"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
    CLOSED = "closed"


class ReconnectionStrategy(Enum):
    """Reconnection strategy"""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    ADAPTIVE = "adaptive"


@dataclass
class ConnectionMetrics:
    """Connection performance metrics"""
    connection_id: str
    state: ConnectionState
    connected_at: Optional[datetime]
    last_activity: datetime
    reconnect_count: int
    total_reconnects: int
    connection_time: float
    disconnection_time: float
    average_reconnect_time: float
    messages_sent: int
    messages_received: int
    bytes_sent: int
    bytes_received: int
    error_count: int
    last_error: Optional[str]
    health_score: float = 1.0


@dataclass
class ReconnectionConfig:
    """Reconnection configuration"""
    max_reconnect_attempts: int = 10
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    strategy: ReconnectionStrategy = ReconnectionStrategy.EXPONENTIAL_BACKOFF
    health_check_interval: int = 30
    connection_timeout: int = 10
    ping_interval: int = 30
    ping_timeout: int = 5
    max_idle_time: int = 300
    auto_reconnect: bool = True
    fallback_enabled: bool = True


class WebSocketConnection:
    """Individual WebSocket connection with recovery capabilities"""
    
    def __init__(self, connection_id: str, url: str, config: ReconnectionConfig):
        self.connection_id = connection_id
        self.url = url
        self.config = config
        self.websocket: Optional[websockets.WebSocketServerProtocol] = None
        self.state = ConnectionState.DISCONNECTED
        self._reconnect_task: Optional[asyncio.Task] = None
        self._ping_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Metrics
        self.metrics = ConnectionMetrics(
            connection_id=connection_id,
            state=ConnectionState.DISCONNECTED,
            connected_at=None,
            last_activity=datetime.utcnow(),
            reconnect_count=0,
            total_reconnects=0,
            connection_time=0.0,
            disconnection_time=0.0,
            average_reconnect_time=0.0,
            messages_sent=0,
            messages_received=0,
            bytes_sent=0,
            bytes_received=0,
            error_count=0,
            last_error=None
        )
        
        # Callbacks
        self.on_connect: Optional[Callable] = None
        self.on_disconnect: Optional[Callable] = None
        self.on_message: Optional[Callable] = None
        self.on_error: Optional[Callable] = None
        self.on_reconnect: Optional[Callable] = None
        
        # Message queue for disconnected state
        self.message_queue = asyncio.Queue(maxsize=1000)
        
        logger.info(f"WebSocket connection {connection_id} initialized")
    
    async def connect(self) -> bool:
        """Connect to WebSocket server"""
        try:
            logger.info(f"Connecting WebSocket {self.connection_id} to {self.url}")
            
            self.state = ConnectionState.CONNECTING
            self.metrics.last_activity = datetime.utcnow()
            
            # Attempt connection
            try:
                self.websocket = await asyncio.wait_for(
                    websockets.connect(
                        self.url,
                        ping_interval=self.config.ping_interval,
                        ping_timeout=self.config.ping_timeout,
                        close_timeout=self.config.connection_timeout
                    ),
                    timeout=self.config.connection_timeout
                )
                
            except asyncio.TimeoutError:
                self.metrics.last_error = "Connection timeout"
                self.state = ConnectionState.FAILED
                return False
            except Exception as e:
                self.metrics.last_error = str(e)
                self.state = ConnectionState.FAILED
                return False
            
            # Connection successful
            self.state = ConnectionState.CONNECTED
            self.metrics.connected_at = datetime.utcnow()
            self.metrics.connection_time = time.time()
            
            # Start background tasks
            self._ping_task = asyncio.create_task(self._ping_loop())
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            # Process queued messages
            asyncio.create_task(self._process_queued_messages())
            
            # Call connect callback
            if self.on_connect:
                await self._safe_call(self.on_connect, self.connection_id)
            
            logger.info(f"WebSocket {self.connection_id} connected successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting WebSocket {self.connection_id}: {e}")
            self.metrics.last_error = str(e)
            self.state = ConnectionState.FAILED
            return False
    
    async def disconnect(self, graceful: bool = True) -> bool:
        """Disconnect from WebSocket server"""
        try:
            logger.info(f"Disconnecting WebSocket {self.connection_id}")
            
            self.state = ConnectionState.CLOSED
            self.metrics.disconnection_time = time.time()
            
            # Cancel background tasks
            if self._reconnect_task:
                self._reconnect_task.cancel()
            if self._ping_task:
                self._ping_task.cancel()
            if self._health_check_task:
                self._health_check_task.cancel()
            
            # Close WebSocket connection
            if self.websocket:
                if graceful:
                    await self.websocket.close()
                else:
                    self.websocket.close_connection()
                self.websocket = None
            
            # Call disconnect callback
            if self.on_disconnect:
                await self._safe_call(self.on_disconnect, self.connection_id)
            
            logger.info(f"WebSocket {self.connection_id} disconnected successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket {self.connection_id}: {e}")
            return False
    
    async def send_message(self, message: Any) -> bool:
        """Send a message through WebSocket"""
        try:
            if self.state != ConnectionState.CONNECTED or not self.websocket:
                # Queue message for later
                try:
                    self.message_queue.put_nowait(message)
                    logger.debug(f"Message queued for WebSocket {self.connection_id}")
                    return True
                except asyncio.QueueFull:
                    logger.warning(f"Message queue full for WebSocket {self.connection_id}")
                    return False
            
            # Convert message to JSON if needed
            if not isinstance(message, str):
                message = json.dumps(message)
            
            # Send message
            await self.websocket.send(message)
            
            # Update metrics
            self.metrics.messages_sent += 1
            self.metrics.bytes_sent += len(message.encode('utf-8'))
            self.metrics.last_activity = datetime.utcnow()
            
            logger.debug(f"Message sent to WebSocket {self.connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending message to WebSocket {self.connection_id}: {e}")
            self.metrics.last_error = str(e)
            self.metrics.error_count += 1
            
            # Trigger reconnection
            if self.config.auto_reconnect:
                asyncio.create_task(self._handle_connection_loss())
            
            return False
    
    async def _handle_connection_loss(self):
        """Handle connection loss"""
        try:
            logger.warning(f"Connection loss detected for WebSocket {self.connection_id}")
            
            self.state = ConnectionState.DISCONNECTED
            self.metrics.last_error = "Connection lost"
            
            # Call error callback
            if self.on_error:
                await self._safe_call(self.on_error, self.connection_id, "Connection lost")
            
            # Start reconnection if enabled
            if self.config.auto_reconnect:
                await self._start_reconnection()
                
        except Exception as e:
            logger.error(f"Error handling connection loss for {self.connection_id}: {e}")
    
    async def _start_reconnection(self):
        """Start reconnection process"""
        try:
            if self._reconnect_task and not self._reconnect_task.done():
                return  # Already reconnecting
            
            self.state = ConnectionState.RECONNECTING
            self._reconnect_task = asyncio.create_task(self._reconnection_loop())
            
        except Exception as e:
            logger.error(f"Error starting reconnection for {self.connection_id}: {e}")
    
    async def _reconnection_loop(self):
        """Reconnection loop with backoff strategy"""
        try:
            reconnect_attempts = 0
            
            while (reconnect_attempts < self.config.max_reconnect_attempts and 
                   not self._shutdown_event.is_set() and
                   self.state != ConnectionState.CLOSED):
                
                reconnect_attempts += 1
                self.metrics.reconnect_count = reconnect_attempts
                self.metrics.total_reconnects += 1
                
                logger.info(f"Reconnection attempt {reconnect_attempts}/{self.config.max_reconnect_attempts} for WebSocket {self.connection_id}")
                
                # Calculate delay
                delay = self._calculate_reconnect_delay(reconnect_attempts)
                
                # Wait for delay
                await asyncio.sleep(delay)
                
                # Attempt reconnection
                start_time = time.time()
                success = await self.connect()
                reconnect_time = time.time() - start_time
                
                # Update metrics
                if success:
                    # Update average reconnect time
                    total_reconnects = self.metrics.total_reconnects
                    self.metrics.average_reconnect_time = (
                        (self.metrics.average_reconnect_time * (total_reconnects - 1) + reconnect_time) / total_reconnects
                    )
                    
                    # Call reconnect callback
                    if self.on_reconnect:
                        await self._safe_call(self.on_reconnect, self.connection_id, reconnect_attempts)
                    
                    logger.info(f"WebSocket {self.connection_id} reconnected successfully after {reconnect_attempts} attempts")
                    return
                else:
                    logger.warning(f"Reconnection attempt {reconnect_attempts} failed for WebSocket {self.connection_id}")
            
            # Max attempts reached
            logger.error(f"Max reconnection attempts reached for WebSocket {self.connection_id}")
            self.state = ConnectionState.FAILED
            
            # Call error callback
            if self.on_error:
                await self._safe_call(self.on_error, self.connection_id, "Max reconnection attempts reached")
                
        except Exception as e:
            logger.error(f"Error in reconnection loop for {self.connection_id}: {e}")
            self.state = ConnectionState.FAILED
    
    def _calculate_reconnect_delay(self, attempt: int) -> float:
        """Calculate reconnection delay based on strategy"""
        try:
            if self.config.strategy == ReconnectionStrategy.EXPONENTIAL_BACKOFF:
                delay = self.config.base_delay * (self.config.backoff_multiplier ** (attempt - 1))
            elif self.config.strategy == ReconnectionStrategy.LINEAR_BACKOFF:
                delay = self.config.base_delay * attempt
            elif self.config.strategy == ReconnectionStrategy.FIXED_INTERVAL:
                delay = self.config.base_delay
            elif self.config.strategy == ReconnectionStrategy.ADAPTIVE:
                # Adaptive based on error count
                error_factor = min(self.metrics.error_count / 10, 5)
                delay = self.config.base_delay * (1 + error_factor) * (self.config.backoff_multiplier ** (attempt - 1))
            else:
                delay = self.config.base_delay
            
            # Apply max delay limit
            delay = min(delay, self.config.max_delay)
            
            # Add jitter if enabled
            if self.config.jitter:
                import random
                jitter = random.uniform(0.1, 0.3) * delay
                delay += jitter
            
            return delay
            
        except Exception as e:
            logger.error(f"Error calculating reconnect delay: {e}")
            return self.config.base_delay
    
    async def _ping_loop(self):
        """Ping loop to keep connection alive"""
        try:
            while not self._shutdown_event.is_set() and self.state == ConnectionState.CONNECTED:
                try:
                    if self.websocket:
                        await self.websocket.ping()
                        self.metrics.last_activity = datetime.utcnow()
                    
                    await asyncio.sleep(self.config.ping_interval)
                    
                except Exception as e:
                    logger.error(f"Error in ping loop for {self.connection_id}: {e}")
                    await self._handle_connection_loss()
                    break
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in ping loop for {self.connection_id}: {e}")
    
    async def _health_check_loop(self):
        """Health check loop"""
        try:
            while not self._shutdown_event.is_set():
                try:
                    await asyncio.sleep(self.config.health_check_interval)
                    
                    if self.state == ConnectionState.CONNECTED:
                        await self._perform_health_check()
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in health check loop for {self.connection_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in health check loop for {self.connection_id}: {e}")
    
    async def _perform_health_check(self):
        """Perform health check on connection"""
        try:
            # Check idle time
            idle_time = (datetime.utcnow() - self.metrics.last_activity).total_seconds()
            if idle_time > self.config.max_idle_time:
                logger.warning(f"WebSocket {self.connection_id} idle for {idle_time} seconds")
                await self._handle_connection_loss()
                return
            
            # Check health score
            self.metrics.health_score = self._calculate_health_score()
            
            # If health score is too low, reconnect
            if self.metrics.health_score < 0.3:
                logger.warning(f"WebSocket {self.connection_id} health score too low: {self.metrics.health_score}")
                await self._handle_connection_loss()
                
        except Exception as e:
            logger.error(f"Error performing health check for {self.connection_id}: {e}")
    
    def _calculate_health_score(self) -> float:
        """Calculate connection health score"""
        try:
            score = 1.0
            
            # Penalize high error count
            if self.metrics.error_count > 0:
                score -= min(self.metrics.error_count * 0.1, 0.5)
            
            # Penalize high reconnect count
            if self.metrics.reconnect_count > 0:
                score -= min(self.metrics.reconnect_count * 0.05, 0.3)
            
            # Penalize long average reconnect time
            if self.metrics.average_reconnect_time > 10:
                score -= min((self.metrics.average_reconnect_time - 10) * 0.01, 0.2)
            
            # Ensure score is between 0 and 1
            return max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating health score for {self.connection_id}: {e}")
            return 0.0
    
    async def _process_queued_messages(self):
        """Process queued messages after reconnection"""
        try:
            while not self.message_queue.empty() and self.state == ConnectionState.CONNECTED:
                try:
                    message = self.message_queue.get_nowait()
                    await self.send_message(message)
                except asyncio.QueueEmpty:
                    break
                except Exception as e:
                    logger.error(f"Error processing queued message for {self.connection_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in queued message processing for {self.connection_id}: {e}")
    
    async def _safe_call(self, callback: Callable, *args, **kwargs):
        """Safely call a callback"""
        try:
            if callback:
                await callback(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in callback for {self.connection_id}: {e}")
    
    def get_metrics(self) -> ConnectionMetrics:
        """Get connection metrics"""
        return self.metrics


class WebSocketRecoverySystem:
    """WebSocket recovery system with connection management"""
    
    def __init__(self):
        """Initialize WebSocket recovery system"""
        self.connections: Dict[str, WebSocketConnection] = {}
        self.connection_configs: Dict[str, ReconnectionConfig] = {}
        self.monitoring_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # Default configuration
        self.default_config = ReconnectionConfig()
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'failed_connections': 0,
            'total_reconnections': 0,
            'successful_reconnections': 0,
            'average_reconnect_time': 0.0
        }
        
        logger.info("WebSocket recovery system initialized")
    
    async def start(self):
        """Start the WebSocket recovery system"""
        logger.info("Starting WebSocket recovery system")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("WebSocket recovery system started")
    
    async def stop(self):
        """Stop the WebSocket recovery system"""
        logger.info("Stopping WebSocket recovery system")
        
        # Disconnect all connections
        await self.disconnect_all()
        
        # Cancel monitoring task
        if self.monitoring_task:
            self.monitoring_task.cancel()
        
        logger.info("WebSocket recovery system stopped")
    
    async def create_connection(self, connection_id: str, url: str, 
                              config: Optional[ReconnectionConfig] = None) -> bool:
        """Create a new WebSocket connection"""
        try:
            if connection_id in self.connections:
                logger.warning(f"Connection {connection_id} already exists")
                return False
            
            # Use default config if none provided
            if config is None:
                config = self.default_config
            
            # Create connection
            connection = WebSocketConnection(connection_id, url, config)
            
            # Store connection
            self.connections[connection_id] = connection
            self.connection_configs[connection_id] = config
            
            # Update statistics
            self.stats['total_connections'] += 1
            
            logger.info(f"Created WebSocket connection {connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating WebSocket connection {connection_id}: {e}")
            return False
    
    async def connect(self, connection_id: str) -> bool:
        """Connect a WebSocket connection"""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                logger.error(f"Connection {connection_id} not found")
                return False
            
            success = await connection.connect()
            
            if success:
                self.stats['active_connections'] += 1
                logger.info(f"WebSocket connection {connection_id} connected")
            else:
                self.stats['failed_connections'] += 1
                logger.error(f"WebSocket connection {connection_id} failed to connect")
            
            return success
            
        except Exception as e:
            logger.error(f"Error connecting WebSocket {connection_id}: {e}")
            return False
    
    async def disconnect(self, connection_id: str, graceful: bool = True) -> bool:
        """Disconnect a WebSocket connection"""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                logger.warning(f"Connection {connection_id} not found")
                return False
            
            success = await connection.disconnect(graceful)
            
            if success and connection.state == ConnectionState.CLOSED:
                self.stats['active_connections'] -= 1
                del self.connections[connection_id]
                del self.connection_configs[connection_id]
                logger.info(f"WebSocket connection {connection_id} disconnected")
            
            return success
            
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket {connection_id}: {e}")
            return False
    
    async def disconnect_all(self):
        """Disconnect all WebSocket connections"""
        try:
            logger.info("Disconnecting all WebSocket connections")
            
            # Get all connection IDs
            connection_ids = list(self.connections.keys())
            
            # Disconnect all connections concurrently
            tasks = [self.disconnect(conn_id) for conn_id in connection_ids]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info("All WebSocket connections disconnected")
            
        except Exception as e:
            logger.error(f"Error disconnecting all WebSocket connections: {e}")
    
    async def send_message(self, connection_id: str, message: Any) -> bool:
        """Send a message to a specific connection"""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                logger.warning(f"Connection {connection_id} not found")
                return False
            
            return await connection.send_message(message)
            
        except Exception as e:
            logger.error(f"Error sending message to WebSocket {connection_id}: {e}")
            return False
    
    async def broadcast_message(self, message: Any, exclude: Optional[Set[str]] = None) -> int:
        """Broadcast a message to all connections"""
        try:
            exclude = exclude or set()
            sent_count = 0
            
            for connection_id, connection in self.connections.items():
                if connection_id not in exclude:
                    if await connection.send_message(message):
                        sent_count += 1
            
            logger.debug(f"Broadcast message sent to {sent_count} connections")
            return sent_count
            
        except Exception as e:
            logger.error(f"Error broadcasting message: {e}")
            return 0
    
    async def get_connection_metrics(self, connection_id: str) -> Optional[ConnectionMetrics]:
        """Get metrics for a specific connection"""
        try:
            connection = self.connections.get(connection_id)
            if connection:
                return connection.get_metrics()
            return None
        except Exception as e:
            logger.error(f"Error getting connection metrics: {e}")
            return None
    
    async def get_all_connection_metrics(self) -> Dict[str, ConnectionMetrics]:
        """Get metrics for all connections"""
        try:
            return {
                connection_id: connection.get_metrics()
                for connection_id, connection in self.connections.items()
            }
        except Exception as e:
            logger.error(f"Error getting all connection metrics: {e}")
            return {}
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            # Update active connections count
            self.stats['active_connections'] = len([
                conn for conn in self.connections.values() 
                if conn.state == ConnectionState.CONNECTED
            ])
            
            # Calculate average reconnect time
            if self.connections:
                total_reconnect_time = sum(
                    conn.metrics.average_reconnect_time 
                    for conn in self.connections.values()
                )
                self.stats['average_reconnect_time'] = total_reconnect_time / len(self.connections)
            
            return self.stats.copy()
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Monitor all connections
                await self._monitor_all_connections()
                
                # Update statistics
                await self._update_statistics()
                
                # Wait for next iteration
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)  # Brief delay before retry
    
    async def _monitor_all_connections(self):
        """Monitor all connections"""
        try:
            with self._lock:
                connections = list(self.connections.values())
            
            for connection in connections:
                try:
                    await self._monitor_connection(connection)
                except Exception as e:
                    logger.error(f"Error monitoring connection {connection.connection_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error monitoring all connections: {e}")
    
    async def _monitor_connection(self, connection: WebSocketConnection):
        """Monitor a specific connection"""
        try:
            # Check if connection is in failed state
            if connection.state == ConnectionState.FAILED:
                logger.warning(f"Connection {connection.connection_id} is in failed state")
                
                # Remove connection if max attempts reached
                if connection.metrics.reconnect_count >= connection.config.max_reconnect_attempts:
                    await self.disconnect(connection.connection_id, graceful=False)
            
            # Check connection health
            if connection.state == ConnectionState.CONNECTED:
                health_score = connection.metrics.health_score
                if health_score < 0.2:
                    logger.warning(f"Connection {connection.connection_id} has low health score: {health_score}")
                    
        except Exception as e:
            logger.error(f"Error monitoring connection {connection.connection_id}: {e}")
    
    async def _update_statistics(self):
        """Update system statistics"""
        try:
            # Update connection counts
            total_connections = len(self.connections)
            active_connections = len([
                conn for conn in self.connections.values() 
                if conn.state == ConnectionState.CONNECTED
            ])
            failed_connections = len([
                conn for conn in self.connections.values() 
                if conn.state == ConnectionState.FAILED
            ])
            
            # Update statistics
            self.stats['total_connections'] = total_connections
            self.stats['active_connections'] = active_connections
            self.stats['failed_connections'] = failed_connections
            
            logger.info(f"WebSocket statistics: {active_connections} active, {failed_connections} failed out of {total_connections} total")
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")


# Global WebSocket recovery system instance
websocket_recovery_system = WebSocketRecoverySystem()


async def get_websocket_status(connection_id: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific WebSocket connection"""
    try:
        metrics = await websocket_recovery_system.get_connection_metrics(connection_id)
        if metrics:
            return {
                'connection_id': metrics.connection_id,
                'state': metrics.state.value,
                'connected_at': metrics.connected_at.isoformat() if metrics.connected_at else None,
                'reconnect_count': metrics.reconnect_count,
                'health_score': metrics.health_score,
                'messages_sent': metrics.messages_sent,
                'messages_received': metrics.messages_received,
                'error_count': metrics.error_count,
                'last_error': metrics.last_error
            }
        return None
    except Exception as e:
        logger.error(f"Error getting WebSocket status: {e}")
        return None


async def get_all_websocket_status() -> Dict[str, Any]:
    """Get status of all WebSocket connections"""
    try:
        metrics = await websocket_recovery_system.get_all_connection_metrics()
        return {
            connection_id: {
                'connection_id': metrics.connection_id,
                'state': metrics.state.value,
                'connected_at': metrics.connected_at.isoformat() if metrics.connected_at else None,
                'reconnect_count': metrics.reconnect_count,
                'health_score': metrics.health_score,
                'messages_sent': metrics.messages_sent,
                'messages_received': metrics.messages_received,
                'error_count': metrics.error_count,
                'last_error': metrics.last_error
            }
            for connection_id, metrics in metrics.items()
        }
    except Exception as e:
        logger.error(f"Error getting all WebSocket status: {e}")
        return {}


async def create_websocket_connection(connection_id: str, url: str, config: Optional[Dict[str, Any]] = None) -> str:
    """Create a new WebSocket connection"""
    try:
        # Convert config dict to ReconnectionConfig
        reconnection_config = ReconnectionConfig(**config) if config else None
        
        # Create connection
        success = await websocket_recovery_system.create_connection(connection_id, url, reconnection_config)
        
        if success:
            # Connect the WebSocket
            connect_success = await websocket_recovery_system.connect(connection_id)
            
            if connect_success:
                return f"WebSocket connection {connection_id} created and connected successfully"
            else:
                return f"WebSocket connection {connection_id} created but failed to connect"
        else:
            return f"Failed to create WebSocket connection {connection_id}"
            
    except Exception as e:
        logger.error(f"Error creating WebSocket connection: {e}")
        return f"Error creating WebSocket connection: {e}"


async def send_websocket_message(connection_id: str, message: Any) -> str:
    """Send a message to a WebSocket connection"""
    try:
        success = await websocket_recovery_system.send_message(connection_id, message)
        
        if success:
            return f"Message sent to WebSocket {connection_id} successfully"
        else:
            return f"Failed to send message to WebSocket {connection_id}"
            
    except Exception as e:
        logger.error(f"Error sending WebSocket message: {e}")
        return f"Error sending WebSocket message: {e}"


async def get_websocket_statistics() -> Dict[str, Any]:
    """Get WebSocket recovery statistics"""
    try:
        return await websocket_recovery_system.get_statistics()
    except Exception as e:
        logger.error(f"Error getting WebSocket statistics: {e}")
        return {'error': str(e)}


# Initialize WebSocket recovery system
async def initialize_websocket_recovery():
    """Initialize WebSocket recovery system"""
    try:
        await websocket_recovery_system.start()
        logger.info("WebSocket recovery system initialized")
        return "WebSocket recovery system initialized"
    except Exception as e:
        logger.error(f"Error initializing WebSocket recovery system: {e}")
        return f"Error initializing WebSocket recovery system: {e}"


# Cleanup function
async def cleanup_websocket_recovery():
    """Cleanup WebSocket recovery system"""
    try:
        await websocket_recovery_system.stop()
        logger.info("WebSocket recovery system cleaned up")
        return "WebSocket recovery system cleaned up"
    except Exception as e:
        logger.error(f"Error cleaning up WebSocket recovery system: {e}")
        return f"Error cleaning up WebSocket recovery system: {e}"
