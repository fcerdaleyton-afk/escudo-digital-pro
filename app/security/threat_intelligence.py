"""
MARY V5 SHIELD CORE - Threat Intelligence Module
IOC ingestion, reputation analysis, and offline mode support
"""

import os
import time
import json
import hashlib
import asyncio
import aiohttp
import sqlite3
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import threading

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class IOCType(Enum):
    """Indicators of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"


class ReputationLevel(Enum):
    """Reputation levels"""
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    HIGH_RISK = "high_risk"


@dataclass
class IndicatorOfCompromise:
    """IOC data structure"""
    id: str = field(default_factory=lambda: str(int(time.time() * 1000000)))
    ioc_type: IOCType = IOCType.IP_ADDRESS
    value: str = ""
    reputation: ReputationLevel = ReputationLevel.UNKNOWN
    confidence: float = 0.5
    source: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    description: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['ioc_type'] = self.ioc_type.value
        data['reputation'] = self.reputation.value
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IndicatorOfCompromise':
        """Create IOC from dictionary"""
        data = data.copy()
        data['ioc_type'] = IOCType(data['ioc_type'])
        data['reputation'] = ReputationLevel(data['reputation'])
        data['first_seen'] = datetime.fromisoformat(data['first_seen'])
        data['last_seen'] = datetime.fromisoformat(data['last_seen'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)


class IOCCache:
    """In-memory IOC cache with LRU eviction"""
    
    def __init__(self, max_size: int = 100000):
        self.max_size = max_size
        self.cache = {}
        self.access_order = deque(maxlen=max_size)
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_lookups": 0
        }
    
    def get(self, ioc_type: str, value: str) -> Optional[IndicatorOfCompromise]:
        """Get IOC from cache"""
        key = f"{ioc_type}:{value}"
        self.cache_stats["total_lookups"] += 1
        
        if key in self.cache:
            self.cache_stats["hits"] += 1
            # Move to end (most recently used)
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        
        self.cache_stats["misses"] += 1
        return None
    
    def put(self, ioc: IndicatorOfCompromise):
        """Put IOC in cache"""
        key = f"{ioc.ioc_type.value}:{ioc.value}"
        
        # Remove existing key if present
        if key in self.cache:
            self.access_order.remove(key)
        
        # Evict oldest if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = self.access_order.popleft()
            del self.cache[oldest_key]
            self.cache_stats["evictions"] += 1
        
        self.cache[key] = ioc
        self.access_order.append(key)
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
        self.access_order.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = (
            self.cache_stats["hits"] / self.cache_stats["total_lookups"] * 100
            if self.cache_stats["total_lookups"] > 0 else 0
        )
        
        return {
            "cache_size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": round(hit_rate, 2),
            **self.cache_stats
        }


class ThreatIntelDatabase:
    """Local threat intelligence database"""
    
    def __init__(self, db_path: str = None):
        self.enabled = os.getenv("THREAT_INTEL_DB_ENABLED", "true").lower() == "true"
        
        if db_path is None:
            db_path = os.getenv("THREAT_INTEL_DB_PATH", "/app/data/threat_intel.db")
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        logger.info("Threat intelligence database initialized", enabled=self.enabled, db_path=str(self.db_path))
    
    def _init_database(self):
        """Initialize SQLite database"""
        if not self.enabled:
            return
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create IOCs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                reputation TEXT NOT NULL,
                confidence REAL,
                source TEXT,
                first_seen TEXT,
                last_seen TEXT,
                tags TEXT,
                description TEXT,
                context TEXT,
                expires_at TEXT,
                active INTEGER DEFAULT 1
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_reputation ON iocs(reputation)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active)")
        
        conn.commit()
        conn.close()
    
    async def store_ioc(self, ioc: IndicatorOfCompromise) -> bool:
        """Store IOC in database"""
        if not self.enabled:
            return False
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO iocs 
                (id, ioc_type, value, reputation, confidence, source, 
                 first_seen, last_seen, tags, description, context, expires_at, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc.id,
                ioc.ioc_type.value,
                ioc.value,
                ioc.reputation.value,
                ioc.confidence,
                ioc.source,
                ioc.first_seen.isoformat(),
                ioc.last_seen.isoformat(),
                json.dumps(ioc.tags),
                ioc.description,
                json.dumps(ioc.context),
                ioc.expires_at.isoformat() if ioc.expires_at else None,
                1 if ioc.active else 0
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error("Failed to store IOC in database", error=str(e))
            return False
    
    async def get_ioc(self, ioc_type: str, value: str) -> Optional[IndicatorOfCompromise]:
        """Get IOC from database"""
        if not self.enabled:
            return None
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM iocs 
                WHERE ioc_type = ? AND value = ? AND active = 1
            """, (ioc_type, value))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return IndicatorOfCompromise(
                    id=row[0],
                    ioc_type=IOCType(row[1]),
                    value=row[2],
                    reputation=ReputationLevel(row[3]),
                    confidence=row[4],
                    source=row[5],
                    first_seen=datetime.fromisoformat(row[6]),
                    last_seen=datetime.fromisoformat(row[7]),
                    tags=json.loads(row[8]) if row[8] else [],
                    description=row[9] or "",
                    context=json.loads(row[10]) if row[10] else {},
                    expires_at=datetime.fromisoformat(row[11]) if row[11] else None,
                    active=bool(row[12])
                )
            
            return None
            
        except Exception as e:
            logger.error("Failed to get IOC from database", error=str(e))
            return None
    
    async def cleanup_expired_iocs(self):
        """Clean up expired IOCs"""
        if not self.enabled:
            return
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Mark expired IOCs as inactive
            cursor.execute("""
                UPDATE iocs SET active = 0 
                WHERE expires_at IS NOT NULL AND expires_at < ?
            """, (datetime.utcnow().isoformat(),))
            
            # Delete old inactive IOCs (older than 30 days)
            cursor.execute("""
                DELETE FROM iocs 
                WHERE active = 0 AND last_seen < ?
            """, ((datetime.utcnow() - timedelta(days=30)).isoformat(),))
            
            conn.commit()
            conn.close()
            
            logger.info("IOC cleanup completed")
            
        except Exception as e:
            logger.error("IOC cleanup failed", error=str(e))
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Count IOCs by type
            cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs WHERE active = 1 GROUP BY ioc_type")
            ioc_counts = dict(cursor.fetchall())
            
            # Count IOCs by reputation
            cursor.execute("SELECT reputation, COUNT(*) FROM iocs WHERE active = 1 GROUP BY reputation")
            reputation_counts = dict(cursor.fetchall())
            
            # Total counts
            cursor.execute("SELECT COUNT(*) FROM iocs WHERE active = 1")
            total_active = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM iocs WHERE active = 0")
            total_inactive = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "enabled": True,
                "database_path": str(self.db_path),
                "total_active": total_active,
                "total_inactive": total_inactive,
                "by_type": ioc_counts,
                "by_reputation": reputation_counts
            }
            
        except Exception as e:
            logger.error("Failed to get database stats", error=str(e))
            return {"enabled": True, "error": str(e)}


class IOCIngestion:
    """IOC ingestion from various sources"""
    
    def __init__(self):
        self.enabled = os.getenv("IOC_INGESTION_ENABLED", "true").lower() == "true"
        
        # Ingestion sources
        self.sources = self._load_ingestion_sources()
        
        # Ingestion statistics
        self.ingestion_stats = {
            "total_ingested": 0,
            "by_source": defaultdict(int),
            "by_type": defaultdict(int),
            "errors": 0
        }
        
        logger.info("IOC ingestion initialized", enabled=self.enabled)
    
    def _load_ingestion_sources(self) -> Dict[str, Dict[str, Any]]:
        """Load ingestion sources configuration"""
        sources = {}
        
        # File-based sources
        sources["local_file"] = {
            "enabled": os.getenv("IOC_LOCAL_FILE_ENABLED", "false").lower() == "true",
            "path": os.getenv("IOC_LOCAL_FILE_PATH", "/app/data/iocs.json"),
            "format": "json"
        }
        
        # URL-based sources
        sources["threat_feeds"] = {
            "enabled": os.getenv("IOC_THREAT_FEEDS_ENABLED", "false").lower() == "true",
            "urls": os.getenv("IOC_THREAT_FEED_URLS", "").split(",") if os.getenv("IOC_THREAT_FEED_URLS") else [],
            "format": "json",
            "update_interval": int(os.getenv("IOC_UPDATE_INTERVAL", "3600"))  # 1 hour
        }
        
        # API-based sources
        sources["api_feeds"] = {
            "enabled": os.getenv("IOC_API_FEEDS_ENABLED", "false").lower() == "true",
            "endpoints": os.getenv("IOC_API_ENDPOINTS", "").split(",") if os.getenv("IOC_API_ENDPOINTS") else [],
            "api_key": os.getenv("IOC_API_KEY", ""),
            "update_interval": int(os.getenv("IOC_API_UPDATE_INTERVAL", "1800"))  # 30 minutes
        }
        
        return sources
    
    async def ingest_from_file(self, source_config: Dict[str, Any]) -> int:
        """Ingest IOCs from local file"""
        if not source_config["enabled"]:
            return 0
        
        try:
            file_path = Path(source_config["path"])
            if not file_path.exists():
                logger.warning(f"IOC file not found: {file_path}")
                return 0
            
            with open(file_path, 'r', encoding='utf-8') as f:
                if source_config["format"] == "json":
                    data = json.load(f)
                    return await self._process_json_iocs(data, source_config["path"])
                else:
                    logger.error(f"Unsupported file format: {source_config['format']}")
                    return 0
        
        except Exception as e:
            logger.error(f"Failed to ingest from file: {source_config['path']}", error=str(e))
            self.ingestion_stats["errors"] += 1
            return 0
    
    async def ingest_from_url(self, source_config: Dict[str, Any]) -> int:
        """Ingest IOCs from URL"""
        if not source_config["enabled"] or not source_config["urls"]:
            return 0
        
        total_ingested = 0
        
        async with aiohttp.ClientSession() as session:
            for url in source_config["urls"]:
                try:
                    headers = {}
                    if source_config.get("api_key"):
                        headers["Authorization"] = f"Bearer {source_config['api_key']}"
                    
                    async with session.get(url, headers=headers, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            ingested = await self._process_json_iocs(data, url)
                            total_ingested += ingested
                            self.ingestion_stats["by_source"]["url"] += ingested
                        else:
                            logger.warning(f"Failed to fetch IOC from {url}: {response.status}")
                
                except Exception as e:
                    logger.error(f"Failed to ingest from URL: {url}", error=str(e))
                    self.ingestion_stats["errors"] += 1
        
        return total_ingested
    
    async def _process_json_iocs(self, data: Dict[str, Any], source: str) -> int:
        """Process JSON IOC data"""
        ingested = 0
        
        try:
            # Handle different JSON formats
            if "indicators" in data:
                iocs_data = data["indicators"]
            elif "iocs" in data:
                iocs_data = data["iocs"]
            elif isinstance(data, list):
                iocs_data = data
            else:
                iocs_data = [data]
            
            for ioc_data in iocs_data:
                try:
                    ioc = self._parse_ioc_data(ioc_data, source)
                    if ioc:
                        # Store IOC
                        from threat_intelligence import threat_intelligence_manager
                        success = await threat_intelligence_manager.add_ioc(ioc)
                        if success:
                            ingested += 1
                            self.ingestion_stats["by_type"][ioc.ioc_type.value] += 1
                
                except Exception as e:
                    logger.error(f"Failed to parse IOC data: {e}")
                    self.ingestion_stats["errors"] += 1
        
        except Exception as e:
            logger.error(f"Failed to process JSON IOCs: {e}")
            self.ingestion_stats["errors"] += 1
        
        return ingested
    
    def _parse_ioc_data(self, data: Dict[str, Any], source: str) -> Optional[IndicatorOfCompromise]:
        """Parse IOC data from JSON"""
        try:
            # Determine IOC type
            ioc_value = data.get("value") or data.get("indicator") or data.get("ioc")
            if not ioc_value:
                return None
            
            ioc_type = self._determine_ioc_type(ioc_value, data)
            if not ioc_type:
                return None
            
            # Parse reputation
            reputation_str = data.get("reputation", data.get("threat_level", "unknown")).lower()
            reputation = self._parse_reputation(reputation_str)
            
            # Parse confidence
            confidence = float(data.get("confidence", data.get("score", 0.5)))
            confidence = max(0.0, min(1.0, confidence))
            
            # Parse tags
            tags = data.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            
            # Parse context
            context = data.get("context", data.get("metadata", {}))
            
            # Parse expiration
            expires_at = None
            if data.get("expires_at"):
                expires_at = datetime.fromisoformat(data["expires_at"])
            elif data.get("ttl"):
                expires_at = datetime.utcnow() + timedelta(seconds=int(data["ttl"]))
            
            return IndicatorOfCompromise(
                ioc_type=ioc_type,
                value=ioc_value,
                reputation=reputation,
                confidence=confidence,
                source=source,
                tags=tags,
                description=data.get("description", ""),
                context=context,
                expires_at=expires_at
            )
        
        except Exception as e:
            logger.error(f"Failed to parse IOC data: {e}")
            return None
    
    def _determine_ioc_type(self, value: str, data: Dict[str, Any]) -> Optional[IOCType]:
        """Determine IOC type from value and data"""
        # Check if type is explicitly specified
        type_str = data.get("type", data.get("ioc_type", "")).lower()
        if type_str:
            type_mapping = {
                "ip": IOCType.IP_ADDRESS,
                "domain": IOCType.DOMAIN,
                "url": IOCType.URL,
                "hash": IOCType.HASH_SHA256,  # Default hash type
                "hash_md5": IOCType.HASH_MD5,
                "hash_sha1": IOCType.HASH_SHA1,
                "hash_sha256": IOCType.HASH_SHA256,
                "email": IOCType.EMAIL,
                "filename": IOCType.FILENAME,
                "registry": IOCType.REGISTRY_KEY
            }
            
            if type_str in type_mapping:
                return type_mapping[type_str]
        
        # Auto-detect based on value patterns
        value_lower = value.lower()
        
        # IP address
        if self._is_ip_address(value):
            return IOCType.IP_ADDRESS
        
        # Domain
        if self._is_domain(value):
            return IOCType.DOMAIN
        
        # URL
        if value_lower.startswith(("http://", "https://")):
            return IOCType.URL
        
        # Email
        if "@" in value and "." in value.split("@")[-1]:
            return IOCType.EMAIL
        
        # Hash (check length and characters)
        if len(value) in [32, 40, 64] and all(c in "0123456789abcdef" for c in value_lower):
            if len(value) == 32:
                return IOCType.HASH_MD5
            elif len(value) == 40:
                return IOCType.HASH_SHA1
            elif len(value) == 64:
                return IOCType.HASH_SHA256
        
        # Registry key
        if "\\" in value and value_lower.startswith(("hkey_", "hkcu\\", "hklm\\")):
            return IOCType.REGISTRY_KEY
        
        # Filename
        if "." in value and not any(c in value for c in "/\\:"):
            return IOCType.FILENAME
        
        return None
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is a domain"""
        if "." not in value or len(value) < 4:
            return False
        
        # Basic domain validation
        if value.startswith(("http://", "https://", "ftp://")):
            return False
        
        if any(c in value for c in "/\\:"):
            return False
        
        return True
    
    def _parse_reputation(self, reputation_str: str) -> ReputationLevel:
        """Parse reputation string"""
        reputation_mapping = {
            "clean": ReputationLevel.CLEAN,
            "safe": ReputationLevel.CLEAN,
            "good": ReputationLevel.CLEAN,
            "unknown": ReputationLevel.UNKNOWN,
            "suspicious": ReputationLevel.SUSPICIOUS,
            "malicious": ReputationLevel.MALICIOUS,
            "bad": ReputationLevel.MALICIOUS,
            "evil": ReputationLevel.MALICIOUS,
            "high_risk": ReputationLevel.HIGH_RISK,
            "dangerous": ReputationLevel.HIGH_RISK
        }
        
        return reputation_mapping.get(reputation_str, ReputationLevel.UNKNOWN)
    
    def get_ingestion_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics"""
        return {
            "enabled": self.enabled,
            **self.ingestion_stats,
            "sources": {
                name: {
                    "enabled": config["enabled"],
                    "status": "active" if config["enabled"] else "disabled"
                }
                for name, config in self.sources.items()
            }
        }


class ThreatIntelligenceManager:
    """Main threat intelligence manager"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.cache = IOCCache(max_size=int(os.getenv("IOC_CACHE_SIZE", "100000")))
        self.database = ThreatIntelDatabase()
        self.ingestion = IOCIngestion()
        
        # Offline mode
        self.offline_mode = os.getenv("THREAT_INTEL_OFFLINE_MODE", "false").lower() == "true"
        
        # Reputation thresholds
        self.malicious_threshold = float(os.getenv("MALICIOUS_THRESHOLD", "0.8"))
        self.suspicious_threshold = float(os.getenv("SUSPICIOUS_THRESHOLD", "0.6"))
        
        # Update task
        self.update_task = None
        
        logger.info("Threat intelligence manager initialized", enabled=self.enabled, offline=self.offline_mode)
    
    async def start(self):
        """Start threat intelligence services"""
        if not self.enabled:
            return
        
        # Start periodic updates
        self.update_task = asyncio.create_task(self._periodic_updates())
        
        # Initial ingestion
        await self._initial_ingestion()
        
        logger.info("Threat intelligence services started")
    
    async def stop(self):
        """Stop threat intelligence services"""
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Threat intelligence services stopped")
    
    async def check_reputation(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Check reputation of IOC"""
        if not self.enabled:
            return {"reputation": "unknown", "confidence": 0.0, "source": "disabled"}
        
        # Check cache first
        cached_ioc = self.cache.get(ioc_type, value)
        if cached_ioc:
            return {
                "reputation": cached_ioc.reputation.value,
                "confidence": cached_ioc.confidence,
                "source": cached_ioc.source,
                "cached": True,
                "tags": cached_ioc.tags,
                "description": cached_ioc.description
            }
        
        # Check database
        db_ioc = await self.database.get_ioc(ioc_type, value)
        if db_ioc:
            # Cache result
            self.cache.put(db_ioc)
            
            return {
                "reputation": db_ioc.reputation.value,
                "confidence": db_ioc.confidence,
                "source": db_ioc.source,
                "cached": False,
                "tags": db_ioc.tags,
                "description": db_ioc.description
            }
        
        # Default response for unknown IOCs
        return {
            "reputation": "unknown",
            "confidence": 0.0,
            "source": "unknown",
            "cached": False,
            "tags": [],
            "description": "No threat intelligence available"
        }
    
    async def add_ioc(self, ioc: IndicatorOfCompromise) -> bool:
        """Add IOC to threat intelligence"""
        if not self.enabled:
            return False
        
        # Store in database
        success = await self.database.store_ioc(ioc)
        
        if success:
            # Cache the IOC
            self.cache.put(ioc)
            
            # Log addition
            log_audit_event(
                "ioc_added",
                resource=f"ioc:{ioc.ioc_type.value}:{ioc.value}",
                result="success",
                details={
                    "reputation": ioc.reputation.value,
                    "source": ioc.source,
                    "confidence": ioc.confidence
                }
            )
        
        return success
    
    async def _initial_ingestion(self):
        """Perform initial IOC ingestion"""
        if self.offline_mode:
            logger.info("Skipping initial ingestion - offline mode")
            return
        
        logger.info("Starting initial IOC ingestion")
        
        total_ingested = 0
        
        # Ingest from local files
        local_file_config = self.ingestion.sources.get("local_file", {})
        if local_file_config.get("enabled"):
            ingested = await self.ingestion.ingest_from_file(local_file_config)
            total_ingested += ingested
            logger.info(f"Ingested {ingested} IOCs from local file")
        
        # Ingest from URLs
        threat_feeds_config = self.ingestion.sources.get("threat_feeds", {})
        if threat_feeds_config.get("enabled"):
            ingested = await self.ingestion.ingest_from_url(threat_feeds_config)
            total_ingested += ingested
            logger.info(f"Ingested {ingested} IOCs from threat feeds")
        
        logger.info(f"Initial ingestion completed: {total_ingested} IOCs")
    
    async def _periodic_updates(self):
        """Periodic IOC updates"""
        while True:
            try:
                if self.offline_mode:
                    logger.debug("Skipping periodic updates - offline mode")
                else:
                    # Clean up expired IOCs
                    await self.database.cleanup_expired_iocs()
                    
                    # Update from sources
                    await self._update_all_sources()
                
                # Wait for next update
                await asyncio.sleep(3600)  # 1 hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Periodic update error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    async def _update_all_sources(self):
        """Update all IOC sources"""
        total_updated = 0
        
        # Update threat feeds
        threat_feeds_config = self.ingestion.sources.get("threat_feeds", {})
        if threat_feeds_config.get("enabled"):
            updated = await self.ingestion.ingest_from_url(threat_feeds_config)
            total_updated += updated
        
        # Update API feeds
        api_feeds_config = self.ingestion.sources.get("api_feeds", {})
        if api_feeds_config.get("enabled"):
            updated = await self.ingestion.ingest_from_url(api_feeds_config)
            total_updated += updated
        
        if total_updated > 0:
            logger.info(f"Updated {total_updated} IOCs")
    
    def get_threat_intel_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return {
            "enabled": self.enabled,
            "offline_mode": self.offline_mode,
            "cache_stats": self.cache.get_stats(),
            "database_stats": self.database.get_database_stats(),
            "ingestion_stats": self.ingestion.get_ingestion_stats(),
            "thresholds": {
                "malicious": self.malicious_threshold,
                "suspicious": self.suspicious_threshold
            }
        }


# Global threat intelligence manager
threat_intelligence_manager = ThreatIntelligenceManager()


async def start_threat_intelligence():
    """Start threat intelligence services"""
    await threat_intelligence_manager.start()


async def stop_threat_intelligence():
    """Stop threat intelligence services"""
    await threat_intelligence_manager.stop()


async def check_ioc_reputation(ioc_type: str, value: str) -> Dict[str, Any]:
    """Check IOC reputation"""
    return await threat_intelligence_manager.check_reputation(ioc_type, value)


async def add_threat_ioc(ioc_type: str, value: str, reputation: str, 
                       source: str = "manual", **kwargs) -> bool:
    """Add threat IOC"""
    ioc = IndicatorOfCompromise(
        ioc_type=IOCType(ioc_type),
        value=value,
        reputation=ReputationLevel(reputation),
        source=source,
        **kwargs
    )
    return await threat_intelligence_manager.add_ioc(ioc)


def get_threat_intel_stats() -> Dict[str, Any]:
    """Get threat intelligence statistics"""
    return threat_intelligence_manager.get_threat_intel_stats()
