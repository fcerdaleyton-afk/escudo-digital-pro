#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - High Availability Package
Comprehensive HA system with horizontal scaling, stateless design, and distributed coordination
"""

from .high_availability import (
    HighAvailabilityCoordinator, NodeStatus, LockType, ScalingPolicy,
    initialize_ha_system, stop_ha_system, get_ha_status,
    register_ha_node, acquire_distributed_lock, release_distributed_lock,
    create_user_session, get_shared_state, set_shared_state
)

__all__ = [
    'HighAvailabilityCoordinator',
    'NodeStatus',
    'LockType', 
    'ScalingPolicy',
    'initialize_ha_system',
    'stop_ha_system',
    'get_ha_status',
    'register_ha_node',
    'acquire_distributed_lock',
    'release_distributed_lock',
    'create_user_session',
    'get_shared_state',
    'set_shared_state'
]
