#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Defensive Simulation Mode
Safe attack simulation, telemetry replay, and defensive training system
"""

import os
import sys
import asyncio
import logging
import json
import time
import uuid
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
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
        logging.FileHandler('/app/logs/defensive_simulation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SimulationMode(Enum):
    """Simulation mode enumeration"""
    TRAINING = "training"
    REPLAY = "replay"
    VALIDATION = "validation"
    TESTING = "testing"


class AttackType(Enum):
    """Attack type enumeration"""
    PHISHING = "phishing"
    MALWARE = "malware"
    DDOS = "ddos"
    INJECTION = "injection"
    BRUTE_FORCE = "brute_force"
    SOCIAL_ENGINEERING = "social_engineering"
    ADVANCED_PERSISTENT_THREAT = "apt"
    RANSOMWARE = "ransomware"


class DifficultyLevel(Enum):
    """Difficulty level enumeration"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class SimulationStatus(Enum):
    """Simulation status enumeration"""
    PREPARING = "preparing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AttackScenario:
    """Attack scenario data structure"""
    scenario_id: str
    name: str
    description: str
    attack_type: AttackType
    difficulty: DifficultyLevel
    duration: int  # seconds
    objectives: List[str]
    success_criteria: List[str]
    telemetry_data: List[Dict[str, Any]]
    simulation_config: Dict[str, Any]
    safety_constraints: List[str]
    learning_objectives: List[str]


@dataclass
class SimulationSession:
    """Simulation session data structure"""
    session_id: str
    scenario_id: str
    user_id: str
    mode: SimulationMode
    status: SimulationStatus
    start_time: datetime
    end_time: Optional[datetime]
    progress: float
    score: float
    actions_taken: List[Dict[str, Any]]
    metrics_collected: Dict[str, Any]
    achievements: List[str]
    feedback: Dict[str, Any]


@dataclass
class TelemetryEvent:
    """Telemetry event data structure"""
    event_id: str
    timestamp: datetime
    event_type: str
    source: str
    data: Dict[str, Any]
    severity: str
    context: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class TrainingExercise:
    """Training exercise data structure"""
    exercise_id: str
    title: str
    description: str
    instructions: List[str]
    expected_actions: List[str]
    hints: List[str]
    time_limit: Optional[int]
    scoring_criteria: Dict[str, Any]
    prerequisites: List[str]


class SafeAttackSimulator:
    """Safe attack simulation system"""
    
    def __init__(self):
        """Initialize safe attack simulator"""
        self.scenarios: Dict[str, AttackScenario] = {}
        self.active_sessions: Dict[str, SimulationSession] = {}
        self.sandbox_environment: bool = True
        self.isolation_enabled: bool = True
        self.real_time_protection: bool = True
        
        # Attack patterns and behaviors
        self.attack_patterns: Dict[str, List[Dict[str, Any]]] = {}
        self.defensive_measures: Dict[str, List[Dict[str, Any]]] = {}
        
        # Simulation constraints
        self.max_concurrent_sessions: int = 10
        self.session_timeout: int = 3600  # 1 hour
        self.safety_checks: List[str] = []
        
        logger.info("Safe attack simulator initialized")
    
    async def initialize(self):
        """Initialize safe attack simulator"""
        try:
            # Load predefined scenarios
            await self._load_predefined_scenarios()
            
            # Initialize attack patterns
            await self._initialize_attack_patterns()
            
            # Setup safety constraints
            await self._setup_safety_constraints()
            
            logger.info("Safe attack simulator initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing safe attack simulator: {e}")
            raise
    
    async def _load_predefined_scenarios(self):
        """Load predefined attack scenarios"""
        try:
            # Phishing scenario
            self.scenarios['phishing_basic'] = AttackScenario(
                scenario_id='phishing_basic',
                name='Basic Phishing Attack',
                description='Simulate a basic phishing email attack targeting internal users',
                attack_type=AttackType.PHISHING,
                difficulty=DifficultyLevel.BEGINNER,
                duration=300,  # 5 minutes
                objectives=[
                    'Identify phishing indicators',
                    'Block malicious emails',
                    'Educate targeted users'
                ],
                success_criteria=[
                    'All phishing emails blocked',
                    'No user credentials compromised',
                    'Security awareness improved'
                ],
                telemetry_data=[],
                simulation_config={
                    'email_count': 50,
                    'target_users': 10,
                    'malicious_links': 5,
                    'attachment_types': ['pdf', 'doc', 'exe']
                },
                safety_constraints=[
                    'no_real_emails_sent',
                    'no_real_user_data_accessed',
                    'sandbox_environment_only'
                ],
                learning_objectives=[
                    'Recognize phishing indicators',
                    'Understand email security',
                    'Practice incident response'
                ]
            )
            
            # DDoS scenario
            self.scenarios['ddos_simple'] = AttackScenario(
                scenario_id='ddos_simple',
                name='Simple DDoS Attack',
                description='Simulate a simple distributed denial of service attack',
                attack_type=AttackType.DDOS,
                difficulty=DifficultyLevel.INTERMEDIATE,
                duration=600,  # 10 minutes
                objectives=[
                    'Detect traffic anomalies',
                    'Implement rate limiting',
                    'Maintain service availability'
                ],
                success_criteria=[
                    'Service remains available',
                    'Attack traffic identified',
                    'Defensive measures effective'
                ],
                telemetry_data=[],
                simulation_config={
                    'attack_intensity': 'medium',
                    'target_services': ['api', 'web'],
                    'botnet_size': 100,
                    'attack_vectors': ['http_flood', 'syn_flood']
                },
                safety_constraints=[
                    'no_real_network_impact',
                    'simulated_traffic_only',
                    'rate_limited_simulation'
                ],
                learning_objectives=[
                    'DDoS detection techniques',
                    'Traffic analysis',
                    'Mitigation strategies'
                ]
            )
            
            # Malware scenario
            self.scenarios['malware_detection'] = AttackScenario(
                scenario_id='malware_detection',
                name='Malware Detection Challenge',
                description='Simulate malware infection and detection challenges',
                attack_type=AttackType.MALWARE,
                difficulty=DifficultyLevel.ADVANCED,
                duration=900,  # 15 minutes
                objectives=[
                    'Detect malware indicators',
                    'Isolate infected systems',
                    'Analyze malware behavior'
                ],
                success_criteria=[
                    'Malware identified and contained',
                    'No lateral movement',
                    'Forensic analysis completed'
                ],
                telemetry_data=[],
                simulation_config={
                    'malware_types': ['trojan', 'ransomware', 'spyware'],
                    'infection_vector': 'email_attachment',
                    'propagation_methods': ['network_share', 'usb']
                },
                safety_constraints=[
                    'no_real_file_system_access',
                    'simulated malware_only',
                    'contained_environment'
                ],
                learning_objectives=[
                    'Malware analysis techniques',
                    'Incident containment',
                    'Forensic investigation'
                ]
            )
            
            # SQL Injection scenario
            self.scenarios['sql_injection'] = AttackScenario(
                scenario_id='sql_injection',
                name='SQL Injection Attack',
                description='Simulate SQL injection attacks on web applications',
                attack_type=AttackType.INJECTION,
                difficulty=DifficultyLevel.INTERMEDIATE,
                duration=450,  # 7.5 minutes
                objectives=[
                    'Identify injection attempts',
                    'Block malicious queries',
                    'Secure database access'
                ],
                success_criteria=[
                    'All injections blocked',
                    'Database integrity maintained',
                    'Security patches applied'
                ],
                telemetry_data=[],
                simulation_config={
                    'target_endpoints': ['/api/users', '/api/data'],
                    'injection_types': ['union_based', 'boolean_based', 'time_based'],
                    'attack_tools': ['sqlmap', 'manual']
                },
                safety_constraints=[
                    'no_real_database_queries',
                    'simulated responses_only',
                    'read_only_simulation'
                ],
                learning_objectives=[
                    'SQL injection detection',
                    'Input validation',
                    'Database security'
                ]
            )
            
            logger.info(f"Loaded {len(self.scenarios)} predefined scenarios")
            
        except Exception as e:
            logger.error(f"Error loading predefined scenarios: {e}")
    
    async def _initialize_attack_patterns(self):
        """Initialize attack patterns"""
        try:
            # Phishing patterns
            self.attack_patterns['phishing'] = [
                {
                    'pattern': 'urgent_email_request',
                    'indicators': ['urgent', 'immediate action', 'security alert'],
                    'techniques': ['spoofed_sender', 'malicious_links', 'attachments'],
                    'defenses': ['email_filtering', 'user_training', 'link_scanning']
                },
                {
                    'pattern': 'credential_harvesting',
                    'indicators': ['login_required', 'account_suspended', 'verify_identity'],
                    'techniques': ['fake_login_pages', 'credential_theft', 'session_hijacking'],
                    'defenses': ['mfa', 'login_monitoring', 'behavioral_analysis']
                }
            ]
            
            # DDoS patterns
            self.attack_patterns['ddos'] = [
                {
                    'pattern': 'http_flood',
                    'indicators': ['high_request_rate', 'resource_exhaustion'],
                    'techniques': ['botnet', 'amplification', 'application_layer'],
                    'defenses': ['rate_limiting', 'cdn', 'load_balancing']
                },
                {
                    'pattern': 'syn_flood',
                    'indicators': ['half_open_connections', 'port_exhaustion'],
                    'techniques': ['ip_spoofing', 'syn_cookies', 'connection_flooding'],
                    'defenses': ['syn_cookies', 'firewall_rules', 'connection_limiting']
                }
            ]
            
            # Malware patterns
            self.attack_patterns['malware'] = [
                {
                    'pattern': 'trojan_infection',
                    'indicators': ['suspicious_processes', 'unusual_network_traffic'],
                    'techniques': ['social_engineering', 'payload_delivery', 'persistence'],
                    'defenses': ['antivirus', 'behavioral_analysis', 'network_segmentation']
                },
                {
                    'pattern': 'ransomware_attack',
                    'indicators': ['file_encryption', 'ransom_notes', 'backup_deletion'],
                    'techniques': ['encryption', 'extortion', 'lateral_movement'],
                    'defenses': ['backup_protection', 'file_integrity', 'network_isolation']
                }
            ]
            
            logger.info(f"Initialized attack patterns for {len(self.attack_patterns)} attack types")
            
        except Exception as e:
            logger.error(f"Error initializing attack patterns: {e}")
    
    async def _setup_safety_constraints(self):
        """Setup safety constraints"""
        try:
            self.safety_checks = [
                'sandbox_environment_active',
                'no_real_system_modification',
                'no_real_network_traffic',
                'no_real_user_interaction',
                'data_isolation_enabled',
                'time_limits_enforced',
                'emergency_stop_available',
                'monitoring_active'
            ]
            
            logger.info("Safety constraints configured")
            
        except Exception as e:
            logger.error(f"Error setting up safety constraints: {e}")
    
    async def start_simulation(self, scenario_id: str, user_id: str, mode: SimulationMode = SimulationMode.TRAINING) -> str:
        """Start a new simulation session"""
        try:
            if scenario_id not in self.scenarios:
                return f"Scenario {scenario_id} not found"
            
            if len(self.active_sessions) >= self.max_concurrent_sessions:
                return "Maximum concurrent sessions reached"
            
            # Create session
            session_id = str(uuid.uuid4())
            scenario = self.scenarios[scenario_id]
            
            session = SimulationSession(
                session_id=session_id,
                scenario_id=scenario_id,
                user_id=user_id,
                mode=mode,
                status=SimulationStatus.PREPARING,
                start_time=datetime.utcnow(),
                end_time=None,
                progress=0.0,
                score=0.0,
                actions_taken=[],
                metrics_collected={},
                achievements=[],
                feedback={}
            )
            
            self.active_sessions[session_id] = session
            
            # Prepare simulation environment
            await self._prepare_simulation_environment(session_id, scenario)
            
            # Start simulation
            await self._start_simulation_execution(session_id, scenario)
            
            logger.info(f"Simulation started: {session_id} for scenario {scenario_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Error starting simulation: {e}")
            return f"Error starting simulation: {e}"
    
    async def _prepare_simulation_environment(self, session_id: str, scenario: AttackScenario):
        """Prepare simulation environment"""
        try:
            session = self.active_sessions[session_id]
            
            # Generate telemetry data
            telemetry_events = await self._generate_telemetry_data(scenario)
            scenario.telemetry_data = telemetry_events
            
            # Setup defensive measures
            await self._setup_defensive_measures(scenario)
            
            # Validate safety constraints
            await self._validate_safety_constraints()
            
            session.status = SimulationStatus.RUNNING
            
            logger.info(f"Simulation environment prepared for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error preparing simulation environment: {e}")
            raise
    
    async def _generate_telemetry_data(self, scenario: AttackScenario) -> List[Dict[str, Any]]:
        """Generate telemetry data for scenario"""
        try:
            telemetry_events = []
            
            # Generate base telemetry
            base_events = [
                {
                    'event_type': 'system_start',
                    'timestamp': datetime.utcnow().isoformat(),
                    'data': {'status': 'normal', 'load': 0.3}
                },
                {
                    'event_type': 'network_activity',
                    'timestamp': datetime.utcnow().isoformat(),
                    'data': {'connections': 100, 'bandwidth': 1000}
                },
                {
                    'event_type': 'user_activity',
                    'timestamp': datetime.utcnow().isoformat(),
                    'data': {'active_users': 50, 'logins': 10}
                }
            ]
            
            # Add scenario-specific telemetry
            if scenario.attack_type == AttackType.PHISHING:
                phishing_events = [
                    {
                        'event_type': 'email_received',
                        'timestamp': (datetime.utcnow() + timedelta(seconds=random.randint(0, 300))).isoformat(),
                        'data': {
                            'sender': 'suspicious@malicious.com',
                            'subject': 'Urgent: Security Alert',
                            'recipients': scenario.simulation_config.get('target_users', 10),
                            'attachments': scenario.simulation_config.get('attachment_types', [])
                        }
                    }
                ]
                base_events.extend(phishing_events)
            
            elif scenario.attack_type == AttackType.DDOS:
                ddos_events = [
                    {
                        'event_type': 'traffic_spike',
                        'timestamp': (datetime.utcnow() + timedelta(seconds=random.randint(0, 600))).isoformat(),
                        'data': {
                            'requests_per_second': random.randint(1000, 10000),
                            'source_ips': scenario.simulation_config.get('botnet_size', 100),
                            'target_service': random.choice(scenario.simulation_config.get('target_services', ['api']))
                        }
                    }
                ]
                base_events.extend(ddos_events)
            
            elif scenario.attack_type == AttackType.MALWARE:
                malware_events = [
                    {
                        'event_type': 'malware_detected',
                        'timestamp': (datetime.utcnow() + timedelta(seconds=random.randint(0, 900))).isoformat(),
                        'data': {
                            'malware_type': random.choice(scenario.simulation_config.get('malware_types', ['trojan'])),
                            'infected_host': f'host-{random.randint(1, 50)}',
                            'detection_method': 'heuristic'
                        }
                    }
                ]
                base_events.extend(malware_events)
            
            elif scenario.attack_type == AttackType.INJECTION:
                injection_events = [
                    {
                        'event_type': 'sql_injection_attempt',
                        'timestamp': (datetime.utcnow() + timedelta(seconds=random.randint(0, 450))).isoformat(),
                        'data': {
                            'endpoint': random.choice(scenario.simulation_config.get('target_endpoints', ['/api'])),
                            'payload': "'; DROP TABLE users; --",
                            'source_ip': f"192.168.1.{random.randint(1, 254)}"
                        }
                    }
                ]
                base_events.extend(injection_events)
            
            return base_events
            
        except Exception as e:
            logger.error(f"Error generating telemetry data: {e}")
            return []
    
    async def _setup_defensive_measures(self, scenario: AttackScenario):
        """Setup defensive measures for scenario"""
        try:
            # Initialize defensive measures based on attack type
            if scenario.attack_type == AttackType.PHISHING:
                self.defensive_measures['phishing'] = [
                    {
                        'measure': 'email_filtering',
                        'effectiveness': 0.8,
                        'configuration': {'spam_threshold': 0.7, 'link_scanning': True}
                    },
                    {
                        'measure': 'user_training',
                        'effectiveness': 0.6,
                        'configuration': {'training_level': 'basic', 'awareness_score': 0.7}
                    }
                ]
            
            elif scenario.attack_type == AttackType.DDOS:
                self.defensive_measures['ddos'] = [
                    {
                        'measure': 'rate_limiting',
                        'effectiveness': 0.7,
                        'configuration': {'requests_per_second': 1000, 'burst_limit': 5000}
                    },
                    {
                        'measure': 'load_balancing',
                        'effectiveness': 0.8,
                        'configuration': {'algorithm': 'round_robin', 'health_checks': True}
                    }
                ]
            
            elif scenario.attack_type == AttackType.MALWARE:
                self.defensive_measures['malware'] = [
                    {
                        'measure': 'antivirus_scanning',
                        'effectiveness': 0.9,
                        'configuration': {'scan_frequency': 'real_time', 'heuristics': True}
                    },
                    {
                        'measure': 'behavioral_analysis',
                        'effectiveness': 0.7,
                        'configuration': {'baseline_learning': True, 'anomaly_threshold': 0.8}
                    }
                ]
            
            elif scenario.attack_type == AttackType.INJECTION:
                self.defensive_measures['injection'] = [
                    {
                        'measure': 'input_validation',
                        'effectiveness': 0.8,
                        'configuration': {'whitelist_mode': True, 'sql_validation': True}
                    },
                    {
                        'measure': 'parameterized_queries',
                        'effectiveness': 0.9,
                        'configuration': {'prepared_statements': True, 'query_sanitization': True}
                    }
                ]
            
            logger.info(f"Defensive measures configured for {scenario.attack_type.value}")
            
        except Exception as e:
            logger.error(f"Error setting up defensive measures: {e}")
    
    async def _validate_safety_constraints(self):
        """Validate safety constraints"""
        try:
            # Check sandbox environment
            if not self.sandbox_environment:
                raise Exception("Sandbox environment not active")
            
            # Check isolation
            if not self.isolation_enabled:
                raise Exception("Isolation not enabled")
            
            # Check real-time protection
            if not self.real_time_protection:
                raise Exception("Real-time protection not enabled")
            
            logger.info("Safety constraints validated")
            
        except Exception as e:
            logger.error(f"Safety constraint validation failed: {e}")
            raise
    
    async def _start_simulation_execution(self, session_id: str, scenario: AttackScenario):
        """Start simulation execution"""
        try:
            session = self.active_sessions[session_id]
            
            # Start telemetry playback
            asyncio.create_task(self._playback_telemetry(session_id, scenario))
            
            # Start attack simulation
            asyncio.create_task(self._simulate_attack(session_id, scenario))
            
            # Start progress monitoring
            asyncio.create_task(self._monitor_progress(session_id, scenario))
            
            logger.info(f"Simulation execution started for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error starting simulation execution: {e}")
            session.status = SimulationStatus.FALED
    
    async def _playback_telemetry(self, session_id: str, scenario: AttackScenario):
        """Playback telemetry data"""
        try:
            session = self.active_sessions[session_id]
            
            for event in scenario.telemetry_data:
                if session.status != SimulationStatus.RUNNING:
                    break
                
                # Create telemetry event
                telemetry_event = TelemetryEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.fromisoformat(event['timestamp']),
                    event_type=event['event_type'],
                    source='simulation',
                    data=event['data'],
                    severity='info',
                    context={'session_id': session_id, 'scenario_id': scenario.scenario_id},
                    metadata={'simulation': True}
                )
                
                # Send to monitoring systems
                await self._send_telemetry_event(telemetry_event)
                
                # Wait for next event
                await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Error in telemetry playback: {e}")
    
    async def _simulate_attack(self, session_id: str, scenario: AttackScenario):
        """Simulate attack execution"""
        try:
            session = self.active_sessions[session_id]
            
            # Get attack patterns
            patterns = self.attack_patterns.get(scenario.attack_type.value, [])
            
            # Simulate attack phases
            for phase in range(3):  # 3 phases
                if session.status != SimulationStatus.RUNNING:
                    break
                
                # Generate attack events
                attack_events = await self._generate_attack_events(scenario, phase)
                
                for event in attack_events:
                    if session.status != SimulationStatus.RUNNING:
                        break
                    
                    # Send attack event
                    await self._send_attack_event(session_id, event)
                    
                    # Wait between events
                    await asyncio.sleep(2)
                
                # Wait between phases
                await asyncio.sleep(10)
            
        except Exception as e:
            logger.error(f"Error in attack simulation: {e}")
    
    async def _generate_attack_events(self, scenario: AttackScenario, phase: int) -> List[Dict[str, Any]]:
        """Generate attack events"""
        try:
            events = []
            
            if scenario.attack_type == AttackType.PHISHING:
                events = [
                    {
                        'event_type': 'phishing_email_sent',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {
                            'emails_sent': scenario.simulation_config.get('email_count', 50),
                            'malicious_links': scenario.simulation_config.get('malicious_links', 5),
                            'phase': phase
                        }
                    }
                ]
            
            elif scenario.attack_type == AttackType.DDOS:
                events = [
                    {
                        'event_type': 'ddos_attack_started',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {
                            'attack_intensity': scenario.simulation_config.get('attack_intensity', 'medium'),
                            'target_services': scenario.simulation_config.get('target_services', []),
                            'phase': phase
                        }
                    }
                ]
            
            elif scenario.attack_type == AttackType.MALWARE:
                events = [
                    {
                        'event_type': 'malware_infection',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {
                            'malware_type': random.choice(scenario.simulation_config.get('malware_types', [])),
                            'infection_vector': scenario.simulation_config.get('infection_vector', ''),
                            'phase': phase
                        }
                    }
                ]
            
            elif scenario.attack_type == AttackType.INJECTION:
                events = [
                    {
                        'event_type': 'sql_injection_attempt',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {
                            'target_endpoint': random.choice(scenario.simulation_config.get('target_endpoints', [])),
                            'injection_type': random.choice(scenario.simulation_config.get('injection_types', [])),
                            'phase': phase
                        }
                    }
                ]
            
            return events
            
        except Exception as e:
            logger.error(f"Error generating attack events: {e}")
            return []
    
    async def _send_telemetry_event(self, event: TelemetryEvent):
        """Send telemetry event to monitoring systems"""
        try:
            # In a real implementation, this would send to monitoring systems
            logger.debug(f"Telemetry event: {event.event_type}")
            
        except Exception as e:
            logger.error(f"Error sending telemetry event: {e}")
    
    async def _send_attack_event(self, session_id: str, event: Dict[str, Any]):
        """Send attack event"""
        try:
            session = self.active_sessions[session_id]
            
            # Add to session actions
            session.actions_taken.append({
                'timestamp': datetime.utcnow().isoformat(),
                'type': 'attack_event',
                'data': event
            })
            
            logger.info(f"Attack event in session {session_id}: {event['event_type']}")
            
        except Exception as e:
            logger.error(f"Error sending attack event: {e}")
    
    async def _monitor_progress(self, session_id: str, scenario: AttackScenario):
        """Monitor simulation progress"""
        try:
            session = self.active_sessions[session_id]
            
            while session.status == SimulationStatus.RUNNING:
                # Calculate progress based on time
                elapsed = (datetime.utcnow() - session.start_time).total_seconds()
                progress = min(elapsed / scenario.duration, 1.0)
                session.progress = progress
                
                # Check if simulation should end
                if elapsed >= scenario.duration:
                    await self._complete_simulation(session_id)
                    break
                
                await asyncio.sleep(5)
            
        except Exception as e:
            logger.error(f"Error monitoring progress: {e}")
    
    async def _complete_simulation(self, session_id: str):
        """Complete simulation session"""
        try:
            session = self.active_sessions[session_id]
            
            session.status = SimulationStatus.COMPLETED
            session.end_time = datetime.utcnow()
            
            # Calculate final score
            session.score = await self._calculate_score(session_id)
            
            # Generate feedback
            session.feedback = await self._generate_feedback(session_id)
            
            logger.info(f"Simulation completed: {session_id} with score {session.score}")
            
        except Exception as e:
            logger.error(f"Error completing simulation: {e}")
    
    async def _calculate_score(self, session_id: str) -> float:
        """Calculate simulation score"""
        try:
            session = self.active_sessions[session_id]
            scenario = self.scenarios[session.scenario_id]
            
            # Base score
            score = 50.0
            
            # Progress bonus
            score += session.progress * 30
            
            # Actions taken bonus
            action_score = min(len(session.actions_taken) * 2, 20)
            score += action_score
            
            return min(score, 100.0)
            
        except Exception as e:
            logger.error(f"Error calculating score: {e}")
            return 0.0
    
    async def _generate_feedback(self, session_id: str) -> Dict[str, Any]:
        """Generate feedback for session"""
        try:
            session = self.active_sessions[session_id]
            scenario = self.scenarios[session.scenario_id]
            
            feedback = {
                'overall_score': session.score,
                'objectives_met': [],
                'improvements': [],
                'achievements': session.achievements,
                'recommendations': []
            }
            
            # Check objectives
            for objective in scenario.objectives:
                if random.random() > 0.3:  # 70% chance of meeting objectives
                    feedback['objectives_met'].append(objective)
                else:
                    feedback['improvements'].append(f"Need to work on: {objective}")
            
            # Add recommendations
            feedback['recommendations'] = [
                "Practice regular security drills",
                "Review security policies",
                "Improve monitoring capabilities"
            ]
            
            return feedback
            
        except Exception as e:
            logger.error(f"Error generating feedback: {e}")
            return {}
    
    async def stop_simulation(self, session_id: str) -> bool:
        """Stop simulation session"""
        try:
            if session_id not in self.active_sessions:
                return False
            
            session = self.active_sessions[session_id]
            session.status = SimulationStatus.CANCELLED
            session.end_time = datetime.utcnow()
            
            logger.info(f"Simulation stopped: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping simulation: {e}")
            return False
    
    async def get_simulation_status(self, session_id: str) -> Dict[str, Any]:
        """Get simulation status"""
        try:
            if session_id not in self.active_sessions:
                return {'error': 'Session not found'}
            
            session = self.active_sessions[session_id]
            scenario = self.scenarios[session.scenario_id]
            
            return {
                'session_id': session.session_id,
                'scenario_id': session.scenario_id,
                'scenario_name': scenario.name,
                'user_id': session.user_id,
                'mode': session.mode.value,
                'status': session.status.value,
                'start_time': session.start_time.isoformat(),
                'end_time': session.end_time.isoformat() if session.end_time else None,
                'progress': session.progress,
                'score': session.score,
                'actions_taken': len(session.actions_taken),
                'feedback': session.feedback,
                'achievements': session.achievements
            }
            
        except Exception as e:
            logger.error(f"Error getting simulation status: {e}")
            return {'error': str(e)}


class TelemetryReplaySystem:
    """Telemetry replay system"""
    
    def __init__(self):
        """Initialize telemetry replay system"""
        self.telemetry_data: Dict[str, List[TelemetryEvent]] = {}
        self.replay_sessions: Dict[str, Dict[str, Any]] = {}
        self.replay_speed: float = 1.0
        self.is_replaying: bool = False
        
        logger.info("Telemetry replay system initialized")
    
    async def load_telemetry_data(self, data_source: str, events: List[Dict[str, Any]]):
        """Load telemetry data for replay"""
        try:
            telemetry_events = []
            
            for event_data in events:
                event = TelemetryEvent(
                    event_id=event_data.get('event_id', str(uuid.uuid4())),
                    timestamp=datetime.fromisoformat(event_data['timestamp']),
                    event_type=event_data['event_type'],
                    source=event_data.get('source', 'unknown'),
                    data=event_data['data'],
                    severity=event_data.get('severity', 'info'),
                    context=event_data.get('context', {}),
                    metadata=event_data.get('metadata', {})
                )
                telemetry_events.append(event)
            
            self.telemetry_data[data_source] = telemetry_events
            logger.info(f"Loaded {len(telemetry_events)} telemetry events from {data_source}")
            
        except Exception as e:
            logger.error(f"Error loading telemetry data: {e}")
    
    async def start_replay(self, data_source: str, start_time: Optional[datetime] = None, 
                          end_time: Optional[datetime] = None, speed: float = 1.0) -> str:
        """Start telemetry replay"""
        try:
            if data_source not in self.telemetry_data:
                return f"Data source {data_source} not found"
            
            replay_id = str(uuid.uuid4())
            
            # Filter events by time range
            events = self.telemetry_data[data_source]
            if start_time:
                events = [e for e in events if e.timestamp >= start_time]
            if end_time:
                events = [e for e in events if e.timestamp <= end_time]
            
            # Sort events by timestamp
            events.sort(key=lambda x: x.timestamp)
            
            self.replay_sessions[replay_id] = {
                'data_source': data_source,
                'events': events,
                'start_time': start_time or events[0].timestamp if events else datetime.utcnow(),
                'end_time': end_time or events[-1].timestamp if events else datetime.utcnow(),
                'speed': speed,
                'current_index': 0,
                'is_active': True,
                'started_at': datetime.utcnow()
            }
            
            # Start replay loop
            asyncio.create_task(self._replay_loop(replay_id))
            
            logger.info(f"Telemetry replay started: {replay_id}")
            return replay_id
            
        except Exception as e:
            logger.error(f"Error starting telemetry replay: {e}")
            return f"Error starting telemetry replay: {e}"
    
    async def _replay_loop(self, replay_id: str):
        """Replay loop"""
        try:
            session = self.replay_sessions[replay_id]
            events = session['events']
            
            for i in range(session['current_index'], len(events)):
                if not session['is_active']:
                    break
                
                event = events[i]
                
                # Send event
                await self._send_replay_event(replay_id, event)
                
                # Update session
                session['current_index'] = i + 1
                
                # Calculate delay
                if i < len(events) - 1:
                    delay = (events[i + 1].timestamp - event.timestamp).total_seconds()
                    delay = delay / session['speed']
                    await asyncio.sleep(delay)
            
            # Complete replay
            session['is_active'] = False
            session['completed_at'] = datetime.utcnow()
            
            logger.info(f"Telemetry replay completed: {replay_id}")
            
        except Exception as e:
            logger.error(f"Error in replay loop: {e}")
    
    async def _send_replay_event(self, replay_id: str, event: TelemetryEvent):
        """Send replay event"""
        try:
            # In a real implementation, this would send to monitoring systems
            logger.debug(f"Replay event: {event.event_type}")
            
        except Exception as e:
            logger.error(f"Error sending replay event: {e}")
    
    async def stop_replay(self, replay_id: str) -> bool:
        """Stop telemetry replay"""
        try:
            if replay_id not in self.replay_sessions:
                return False
            
            session = self.replay_sessions[replay_id]
            session['is_active'] = False
            session['stopped_at'] = datetime.utcnow()
            
            logger.info(f"Telemetry replay stopped: {replay_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping telemetry replay: {e}")
            return False
    
    async def get_replay_status(self, replay_id: str) -> Dict[str, Any]:
        """Get replay status"""
        try:
            if replay_id not in self.replay_sessions:
                return {'error': 'Replay session not found'}
            
            session = self.replay_sessions[replay_id]
            
            return {
                'replay_id': replay_id,
                'data_source': session['data_source'],
                'total_events': len(session['events']),
                'current_index': session['current_index'],
                'progress': session['current_index'] / len(session['events']) if session['events'] else 0,
                'speed': session['speed'],
                'is_active': session['is_active'],
                'started_at': session['started_at'].isoformat(),
                'completed_at': session.get('completed_at'),
                'stopped_at': session.get('stopped_at')
            }
            
        except Exception as e:
            logger.error(f"Error getting replay status: {e}")
            return {'error': str(e)}


class IncidentReplaySystem:
    """Incident replay system"""
    
    def __init__(self):
        """Initialize incident replay system"""
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.replay_sessions: Dict[str, Dict[str, Any]] = {}
        self.is_replaying: bool = False
        
        logger.info("Incident replay system initialized")
    
    async def load_incident(self, incident_id: str, incident_data: Dict[str, Any]):
        """Load incident for replay"""
        try:
            self.incidents[incident_id] = {
                'incident_id': incident_id,
                'title': incident_data.get('title', 'Unknown Incident'),
                'description': incident_data.get('description', ''),
                'timeline': incident_data.get('timeline', []),
                'events': incident_data.get('events', []),
                'responses': incident_data.get('responses', []),
                'outcomes': incident_data.get('outcomes', []),
                'metadata': incident_data.get('metadata', {})
            }
            
            logger.info(f"Loaded incident: {incident_id}")
            
        except Exception as e:
            logger.error(f"Error loading incident: {e}")
    
    async def start_incident_replay(self, incident_id: str, interactive: bool = True) -> str:
        """Start incident replay"""
        try:
            if incident_id not in self.incidents:
                return f"Incident {incident_id} not found"
            
            replay_id = str(uuid.uuid4())
            incident = self.incidents[incident_id]
            
            self.replay_sessions[replay_id] = {
                'incident_id': incident_id,
                'interactive': interactive,
                'current_phase': 0,
                'phases': ['detection', 'analysis', 'response', 'recovery'],
                'is_active': True,
                'started_at': datetime.utcnow(),
                'user_actions': [],
                'decisions_made': []
            }
            
            # Start incident replay loop
            asyncio.create_task(self._incident_replay_loop(replay_id))
            
            logger.info(f"Incident replay started: {replay_id}")
            return replay_id
            
        except Exception as e:
            logger.error(f"Error starting incident replay: {e}")
            return f"Error starting incident replay: {e}"
    
    async def _incident_replay_loop(self, replay_id: str):
        """Incident replay loop"""
        try:
            session = self.replay_sessions[replay_id]
            incident = self.incidents[session['incident_id']]
            
            for phase in session['phases']:
                if not session['is_active']:
                    break
                
                session['current_phase'] = phase
                
                # Simulate phase events
                await self._simulate_incident_phase(replay_id, incident, phase)
                
                # Wait for user interaction if interactive
                if session['interactive']:
                    await self._wait_for_user_interaction(replay_id)
                
                await asyncio.sleep(5)  # Phase transition delay
            
            # Complete replay
            session['is_active'] = False
            session['completed_at'] = datetime.utcnow()
            
            logger.info(f"Incident replay completed: {replay_id}")
            
        except Exception as e:
            logger.error(f"Error in incident replay loop: {e}")
    
    async def _simulate_incident_phase(self, replay_id: str, incident: Dict[str, Any], phase: str):
        """Simulate incident phase"""
        try:
            session = self.replay_sessions[replay_id]
            
            # Generate phase events
            if phase == 'detection':
                events = [
                    {
                        'type': 'alert_triggered',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {'alert_type': 'security', 'severity': 'high'}
                    }
                ]
            elif phase == 'analysis':
                events = [
                    {
                        'type': 'investigation_started',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {'investigator': 'auto', 'method': 'automated'}
                    }
                ]
            elif phase == 'response':
                events = [
                    {
                        'type': 'response_initiated',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {'response_type': 'containment', 'status': 'in_progress'}
                    }
                ]
            elif phase == 'recovery':
                events = [
                    {
                        'type': 'recovery_started',
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': {'recovery_type': 'system_restore', 'status': 'in_progress'}
                    }
                ]
            
            # Send events
            for event in events:
                await self._send_incident_event(replay_id, event)
                await asyncio.sleep(2)
            
        except Exception as e:
            logger.error(f"Error simulating incident phase: {e}")
    
    async def _wait_for_user_interaction(self, replay_id: str):
        """Wait for user interaction"""
        try:
            session = self.replay_sessions[replay_id]
            
            # Wait for user action (in real implementation, this would wait for user input)
            await asyncio.sleep(10)
            
            # Simulate user action
            session['user_actions'].append({
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'continue',
                'phase': session['current_phase']
            })
            
        except Exception as e:
            logger.error(f"Error waiting for user interaction: {e}")
    
    async def _send_incident_event(self, replay_id: str, event: Dict[str, Any]):
        """Send incident event"""
        try:
            # In a real implementation, this would send to monitoring systems
            logger.debug(f"Incident event: {event['type']}")
            
        except Exception as e:
            logger.error(f"Error sending incident event: {e}")
    
    async def stop_incident_replay(self, replay_id: str) -> bool:
        """Stop incident replay"""
        try:
            if replay_id not in self.replay_sessions:
                return False
            
            session = self.replay_sessions[replay_id]
            session['is_active'] = False
            session['stopped_at'] = datetime.utcnow()
            
            logger.info(f"Incident replay stopped: {replay_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping incident replay: {e}")
            return False


class TrainingMode:
    """Training mode system"""
    
    def __init__(self):
        """Initialize training mode"""
        self.exercises: Dict[str, TrainingExercise] = []
        self.training_sessions: Dict[str, Dict[str, Any]] = {}
        self.user_progress: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Training mode initialized")
    
    async def create_exercise(self, exercise_id: str, exercise_data: Dict[str, Any]):
        """Create training exercise"""
        try:
            exercise = TrainingExercise(
                exercise_id=exercise_id,
                title=exercise_data.get('title', 'Unknown Exercise'),
                description=exercise_data.get('description', ''),
                instructions=exercise_data.get('instructions', []),
                expected_actions=exercise_data.get('expected_actions', []),
                hints=exercise_data.get('hints', []),
                time_limit=exercise_data.get('time_limit'),
                scoring_criteria=exercise_data.get('scoring_criteria', {}),
                prerequisites=exercise_data.get('prerequisites', [])
            )
            
            self.exercises[exercise_id] = exercise
            logger.info(f"Created training exercise: {exercise_id}")
            
        except Exception as e:
            logger.error(f"Error creating training exercise: {e}")
    
    async def start_training_session(self, exercise_id: str, user_id: str) -> str:
        """Start training session"""
        try:
            if exercise_id not in self.exercises:
                return f"Exercise {exercise_id} not found"
            
            session_id = str(uuid.uuid4())
            exercise = self.exercises[exercise_id]
            
            self.training_sessions[session_id] = {
                'exercise_id': exercise_id,
                'user_id': user_id,
                'start_time': datetime.utcnow(),
                'end_time': None,
                'status': 'in_progress',
                'actions_taken': [],
                'hints_used': [],
                'score': 0.0,
                'feedback': {}
            }
            
            # Start exercise
            asyncio.create_task(self._run_exercise(session_id, exercise))
            
            logger.info(f"Training session started: {session_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Error starting training session: {e}")
            return f"Error starting training session: {e}"
    
    async def _run_exercise(self, session_id: str, exercise: TrainingExercise):
        """Run training exercise"""
        try:
            session = self.training_sessions[session_id]
            
            # Display instructions
            for instruction in exercise.instructions:
                if session['status'] != 'in_progress':
                    break
                
                await self._display_instruction(session_id, instruction)
                await asyncio.sleep(3)
            
            # Wait for user actions
            if exercise.time_limit:
                await asyncio.wait_for(
                    self._wait_for_exercise_completion(session_id),
                    timeout=exercise.time_limit
                )
            else:
                await self._wait_for_exercise_completion(session_id)
            
            # Complete exercise
            await self._complete_exercise(session_id, exercise)
            
        except asyncio.TimeoutError:
            await self._timeout_exercise(session_id, exercise)
        except Exception as e:
            logger.error(f"Error running exercise: {e}")
    
    async def _display_instruction(self, session_id: str, instruction: str):
        """Display instruction"""
        try:
            # In a real implementation, this would display to user interface
            logger.info(f"Instruction for session {session_id}: {instruction}")
            
        except Exception as e:
            logger.error(f"Error displaying instruction: {e}")
    
    async def _wait_for_exercise_completion(self, session_id: str):
        """Wait for exercise completion"""
        try:
            session = self.training_sessions[session_id]
            
            while session['status'] == 'in_progress':
                await asyncio.sleep(1)
                
                # Check for completion conditions
                if len(session['actions_taken']) >= 5:  # Simplified completion
                    break
            
        except Exception as e:
            logger.error(f"Error waiting for exercise completion: {e}")
    
    async def _complete_exercise(self, session_id: str, exercise: TrainingExercise):
        """Complete exercise"""
        try:
            session = self.training_sessions[session_id]
            session['status'] = 'completed'
            session['end_time'] = datetime.utcnow()
            
            # Calculate score
            session['score'] = await self._calculate_exercise_score(session_id, exercise)
            
            # Generate feedback
            session['feedback'] = await self._generate_exercise_feedback(session_id, exercise)
            
            # Update user progress
            await self._update_user_progress(session['user_id'], session_id, exercise)
            
            logger.info(f"Exercise completed: {session_id} with score {session['score']}")
            
        except Exception as e:
            logger.error(f"Error completing exercise: {e}")
    
    async def _calculate_exercise_score(self, session_id: str, exercise: TrainingExercise) -> float:
        """Calculate exercise score"""
        try:
            session = self.training_sessions[session_id]
            
            # Base score
            score = 50.0
            
            # Actions taken bonus
            action_score = min(len(session['actions_taken']) * 10, 30)
            score += action_score
            
            # Hints penalty
            hint_penalty = len(session['hints_used']) * 5
            score -= hint_penalty
            
            return max(score, 0.0)
            
        except Exception as e:
            logger.error(f"Error calculating exercise score: {e}")
            return 0.0
    
    async def _generate_exercise_feedback(self, session_id: str, exercise: TrainingExercise) -> Dict[str, Any]:
        """Generate exercise feedback"""
        try:
            session = self.training_sessions[session_id]
            
            feedback = {
                'score': session['score'],
                'actions_taken': len(session['actions_taken']),
                'hints_used': len(session['hints_used']),
                'recommendations': [],
                'achievements': []
            }
            
            # Add recommendations
            if session['score'] < 70:
                feedback['recommendations'].append("Review the exercise instructions carefully")
                feedback['recommendations'].append("Practice similar exercises to improve")
            
            # Add achievements
            if session['score'] >= 90:
                feedback['achievements'].append("Excellent Performance")
            elif len(session['hints_used']) == 0:
                feedback['achievements'].append("No Hints Used")
            
            return feedback
            
        except Exception as e:
            logger.error(f"Error generating exercise feedback: {e}")
            return {}
    
    async def _update_user_progress(self, user_id: str, session_id: str, exercise: TrainingExercise):
        """Update user progress"""
        try:
            if user_id not in self.user_progress:
                self.user_progress[user_id] = {
                    'completed_exercises': [],
                    'total_score': 0.0,
                    'achievements': [],
                    'last_activity': datetime.utcnow()
                }
            
            progress = self.user_progress[user_id]
            session = self.training_sessions[session_id]
            
            progress['completed_exercises'].append(exercise.exercise_id)
            progress['total_score'] += session['score']
            progress['last_activity'] = datetime.utcnow()
            
            logger.info(f"Updated progress for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error updating user progress: {e}")
    
    async def _timeout_exercise(self, session_id: str, exercise: TrainingExercise):
        """Handle exercise timeout"""
        try:
            session = self.training_sessions[session_id]
            session['status'] = 'timeout'
            session['end_time'] = datetime.utcnow()
            session['feedback'] = {'message': 'Exercise timed out', 'score': 0.0}
            
            logger.info(f"Exercise timed out: {session_id}")
            
        except Exception as e:
            logger.error(f"Error handling exercise timeout: {e}")


class ObservabilityValidation:
    """Observability validation system"""
    
    def __init__(self):
        """Initialize observability validation"""
        self.validation_criteria: Dict[str, Dict[str, Any]] = {}
        self.validation_results: Dict[str, Dict[str, Any]] = {}
        self.metrics_collected: Dict[str, List[Dict[str, Any]]] = {}
        
        logger.info("Observability validation initialized")
    
    async def setup_validation_criteria(self, criteria_id: str, criteria_config: Dict[str, Any]):
        """Setup validation criteria"""
        try:
            self.validation_criteria[criteria_id] = {
                'criteria_id': criteria_id,
                'metrics_required': criteria_config.get('metrics_required', []),
                'thresholds': criteria_config.get('thresholds', {}),
                'compliance_rules': criteria_config.get('compliance_rules', []),
                'validation_frequency': criteria_config.get('validation_frequency', 300),  # 5 minutes
                'alert_thresholds': criteria_config.get('alert_thresholds', {})
            }
            
            logger.info(f"Validation criteria setup: {criteria_id}")
            
        except Exception as e:
            logger.error(f"Error setting up validation criteria: {e}")
    
    async def start_validation(self, criteria_id: str) -> str:
        """Start observability validation"""
        try:
            if criteria_id not in self.validation_criteria:
                return f"Validation criteria {criteria_id} not found"
            
            validation_id = str(uuid.uuid4())
            
            self.validation_results[validation_id] = {
                'criteria_id': criteria_id,
                'start_time': datetime.utcnow(),
                'status': 'running',
                'results': {},
                'violations': [],
                'compliance_score': 0.0
            }
            
            # Start validation loop
            asyncio.create_task(self._validation_loop(validation_id, criteria_id))
            
            logger.info(f"Observability validation started: {validation_id}")
            return validation_id
            
        except Exception as e:
            logger.error(f"Error starting validation: {e}")
            return f"Error starting validation: {e}"
    
    async def _validation_loop(self, validation_id: str, criteria_id: str):
        """Validation loop"""
        try:
            criteria = self.validation_criteria[criteria_id]
            result = self.validation_results[validation_id]
            
            while result['status'] == 'running':
                # Collect metrics
                metrics = await self._collect_metrics(criteria)
                
                # Validate metrics
                violations = await self._validate_metrics(criteria, metrics)
                
                # Update results
                result['results'] = metrics
                result['violations'] = violations
                result['compliance_score'] = await self._calculate_compliance_score(criteria, violations)
                
                # Wait for next validation
                await asyncio.sleep(criteria['validation_frequency'])
            
        except Exception as e:
            logger.error(f"Error in validation loop: {e}")
    
    async def _collect_metrics(self, criteria: Dict[str, Any]) -> Dict[str, Any]:
        """Collect metrics for validation"""
        try:
            metrics = {}
            
            # Collect required metrics
            for metric in criteria['metrics_required']:
                # Simulate metric collection
                if metric == 'system_health':
                    metrics[metric] = random.uniform(0.8, 1.0)
                elif metric == 'response_time':
                    metrics[metric] = random.uniform(10, 100)
                elif metric == 'error_rate':
                    metrics[metric] = random.uniform(0.01, 0.05)
                elif metric == 'throughput':
                    metrics[metric] = random.uniform(1000, 10000)
                else:
                    metrics[metric] = random.uniform(0, 100)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return {}
    
    async def _validate_metrics(self, criteria: Dict[str, Any], metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate metrics against criteria"""
        try:
            violations = []
            
            # Check thresholds
            for metric, threshold in criteria['thresholds'].items():
                if metric in metrics:
                    value = metrics[metric]
                    
                    if isinstance(threshold, dict):
                        if threshold.get('min') and value < threshold['min']:
                            violations.append({
                                'metric': metric,
                                'value': value,
                                'threshold': threshold['min'],
                                'type': 'below_minimum'
                            })
                        elif threshold.get('max') and value > threshold['max']:
                            violations.append({
                                'metric': metric,
                                'value': value,
                                'threshold': threshold['max'],
                                'type': 'above_maximum'
                            })
                    elif isinstance(threshold, (int, float)):
                        if value > threshold:
                            violations.append({
                                'metric': metric,
                                'value': value,
                                'threshold': threshold,
                                'type': 'above_threshold'
                            })
            
            return violations
            
        except Exception as e:
            logger.error(f"Error validating metrics: {e}")
            return []
    
    async def _calculate_compliance_score(self, criteria: Dict[str, Any], violations: List[Dict[str, Any]]) -> float:
        """Calculate compliance score"""
        try:
            total_metrics = len(criteria['metrics_required'])
            if total_metrics == 0:
                return 100.0
            
            violated_metrics = len(set(v['metric'] for v in violations))
            compliant_metrics = total_metrics - violated_metrics
            
            return (compliant_metrics / total_metrics) * 100.0
            
        except Exception as e:
            logger.error(f"Error calculating compliance score: {e}")
            return 0.0
    
    async def stop_validation(self, validation_id: str) -> bool:
        """Stop observability validation"""
        try:
            if validation_id not in self.validation_results:
                return False
            
            result = self.validation_results[validation_id]
            result['status'] = 'stopped'
            result['end_time'] = datetime.utcnow()
            
            logger.info(f"Observability validation stopped: {validation_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping validation: {e}")
            return False
    
    async def get_validation_results(self, validation_id: str) -> Dict[str, Any]:
        """Get validation results"""
        try:
            if validation_id not in self.validation_results:
                return {'error': 'Validation not found'}
            
            return self.validation_results[validation_id]
            
        except Exception as e:
            logger.error(f"Error getting validation results: {e}")
            return {'error': str(e)}


class DefensiveSimulationCoordinator:
    """Main defensive simulation coordinator"""
    
    def __init__(self):
        """Initialize defensive simulation coordinator"""
        self.attack_simulator = SafeAttackSimulator()
        self.telemetry_replay = TelemetryReplaySystem()
        self.incident_replay = IncidentReplaySystem()
        self.training_mode = TrainingMode()
        self.observability_validation = ObservabilityValidation()
        
        self.is_running: bool = False
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Defensive simulation coordinator initialized")
    
    async def start(self):
        """Start defensive simulation coordinator"""
        try:
            logger.info("Starting defensive simulation coordinator")
            
            # Initialize components
            await self.attack_simulator.initialize()
            
            self.is_running = True
            logger.info("Defensive simulation coordinator started successfully")
            
        except Exception as e:
            logger.error(f"Error starting defensive simulation coordinator: {e}")
            raise
    
    async def stop(self):
        """Stop defensive simulation coordinator"""
        try:
            logger.info("Stopping defensive simulation coordinator")
            
            self.is_running = False
            
            logger.info("Defensive simulation coordinator stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping defensive simulation coordinator: {e}")
    
    async def get_simulation_status(self) -> Dict[str, Any]:
        """Get simulation status"""
        try:
            return {
                'is_running': self.is_running,
                'attack_simulator': {
                    'active_sessions': len(self.attack_simulator.active_sessions),
                    'available_scenarios': len(self.attack_simulator.scenarios)
                },
                'telemetry_replay': {
                    'active_replays': len([s for s in self.telemetry_replay.replay_sessions.values() if s['is_active']]),
                    'data_sources': len(self.telemetry_replay.telemetry_data)
                },
                'incident_replay': {
                    'active_replays': len([s for s in self.incident_replay.replay_sessions.values() if s['is_active']]),
                    'loaded_incidents': len(self.incident_replay.incidents)
                },
                'training_mode': {
                    'active_sessions': len([s for s in self.training_mode.training_sessions.values() if s['status'] == 'in_progress']),
                    'available_exercises': len(self.training_mode.exercises)
                },
                'observability_validation': {
                    'active_validations': len([s for s in self.observability_validation.validation_results.values() if s['status'] == 'running']),
                    'validation_criteria': len(self.observability_validation.validation_criteria)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting simulation status: {e}")
            return {'error': str(e)}


# Global defensive simulation coordinator instance
defensive_simulation_coordinator = DefensiveSimulationCoordinator()


# API functions
async def initialize_defensive_simulation() -> str:
    """Initialize defensive simulation system"""
    try:
        await defensive_simulation_coordinator.start()
        logger.info("Defensive simulation system initialized")
        return "Defensive simulation system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing defensive simulation system: {e}")
        return f"Error initializing defensive simulation system: {e}"


async def stop_defensive_simulation() -> str:
    """Stop defensive simulation system"""
    try:
        await defensive_simulation_coordinator.stop()
        logger.info("Defensive simulation system stopped")
        return "Defensive simulation system stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping defensive simulation system: {e}")
        return f"Error stopping defensive simulation system: {e}"


async def start_attack_simulation(scenario_id: str, user_id: str, mode: str = 'training') -> str:
    """Start attack simulation"""
    try:
        mode_enum = SimulationMode(mode)
        result = await defensive_simulation_coordinator.attack_simulator.start_simulation(scenario_id, user_id, mode_enum)
        return result
    except Exception as e:
        logger.error(f"Error starting attack simulation: {e}")
        return f"Error starting attack simulation: {e}"


async def start_telemetry_replay(data_source: str, start_time: Optional[str] = None, 
                               end_time: Optional[str] = None, speed: float = 1.0) -> str:
    """Start telemetry replay"""
    try:
        start_dt = datetime.fromisoformat(start_time) if start_time else None
        end_dt = datetime.fromisoformat(end_time) if end_time else None
        
        result = await defensive_simulation_coordinator.telemetry_replay.start_replay(
            data_source, start_dt, end_dt, speed
        )
        return result
    except Exception as e:
        logger.error(f"Error starting telemetry replay: {e}")
        return f"Error starting telemetry replay: {e}"


async def start_incident_replay(incident_id: str, interactive: bool = True) -> str:
    """Start incident replay"""
    try:
        result = await defensive_simulation_coordinator.incident_replay.start_incident_replay(incident_id, interactive)
        return result
    except Exception as e:
        logger.error(f"Error starting incident replay: {e}")
        return f"Error starting incident replay: {e}"


async def start_training_session(exercise_id: str, user_id: str) -> str:
    """Start training session"""
    try:
        result = await defensive_simulation_coordinator.training_mode.start_training_session(exercise_id, user_id)
        return result
    except Exception as e:
        logger.error(f"Error starting training session: {e}")
        return f"Error starting training session: {e}"


async def start_observability_validation(criteria_id: str) -> str:
    """Start observability validation"""
    try:
        result = await defensive_simulation_coordinator.observability_validation.start_validation(criteria_id)
        return result
    except Exception as e:
        logger.error(f"Error starting observability validation: {e}")
        return f"Error starting observability validation: {e}"


async def get_simulation_status() -> Dict[str, Any]:
    """Get simulation status"""
    try:
        return await defensive_simulation_coordinator.get_simulation_status()
    except Exception as e:
        logger.error(f"Error getting simulation status: {e}")
        return {'error': str(e)}


# Initialize defensive simulation system
async def initialize_simulation_system() -> str:
    """Initialize simulation system"""
    try:
        await initialize_defensive_simulation()
        logger.info("Simulation system initialized")
        return "Simulation system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing simulation system: {e}")
        return f"Error initializing simulation system: {e}"


# Cleanup function
async def cleanup_simulation_system() -> str:
    """Cleanup simulation system"""
    try:
        await stop_defensive_simulation()
        logger.info("Simulation system cleaned up")
        return "Simulation system cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up simulation system: {e}")
        return f"Error cleaning up simulation system: {e}"
