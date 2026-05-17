"""
Performance Optimizer for Mary V5
Production-ready performance optimization and monitoring
"""

import os
import asyncio
import psutil
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from app.core.dependencies import logger


class PerformanceOptimizer:
    """
    Production performance optimizer with monitoring and auto-tuning
    """
    
    def __init__(self):
        self.enabled = os.getenv("PERFORMANCE_OPTIMIZER_ENABLED", "true").lower() == "true"
        
        # Performance thresholds
        self.thresholds = {
            "cpu_usage": float(os.getenv("CPU_THRESHOLD", "80.0")),  # percentage
            "memory_usage": float(os.getenv("MEMORY_THRESHOLD", "85.0")),  # percentage
            "disk_usage": float(os.getenv("DISK_THRESHOLD", "90.0")),  # percentage
            "response_time": float(os.getenv("RESPONSE_TIME_THRESHOLD", "500.0")),  # milliseconds
            "error_rate": float(os.getenv("ERROR_RATE_THRESHOLD", "5.0")),  # percentage
            "concurrent_requests": int(os.getenv("CONCURRENT_REQUESTS_THRESHOLD", "1000"))
        }
        
        # Optimization settings
        self.optimization_level = os.getenv("OPTIMIZATION_LEVEL", "balanced")  # conservative, balanced, aggressive
        self.cache_ttl = int(os.getenv("CACHE_TTL", "300"))  # seconds
        self.connection_pool_size = int(os.getenv("CONNECTION_POOL_SIZE", "100"))
        self.enable_compression = os.getenv("ENABLE_COMPRESSION", "true").lower() == "true"
        
        # Performance metrics
        self.metrics = {
            "requests_per_second": 0.0,
            "avg_response_time": 0.0,
            "error_rate": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "active_connections": 0
        }
        
        # Performance history
        self.performance_history = []
        self.max_history_size = int(os.getenv("PERFORMANCE_HISTORY_SIZE", "1000"))
        
        logger.info("Performance optimizer initialized", enabled=self.enabled, level=self.optimization_level)
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available / (1024 * 1024 * 1024)  # GB
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free = disk.free / (1024 * 1024 * 1024)  # GB
            
            # Network metrics
            network = psutil.net_io_counters()
            network_io = {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
            
            # Process metrics
            process_count = len(psutil.pids())
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu": {
                    "usage_percent": cpu_percent,
                    "core_count": cpu_count,
                    "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                },
                "memory": {
                    "usage_percent": memory_percent,
                    "available_gb": round(memory_available, 2),
                    "total_gb": round(memory.total / (1024 * 1024 * 1024), 2),
                    "used_gb": round(memory.used / (1024 * 1024 * 1024), 2)
                },
                "disk": {
                    "usage_percent": disk_percent,
                    "free_gb": round(disk_free, 2),
                    "total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
                    "used_gb": round(disk.used / (1024 * 1024 * 1024), 2)
                },
                "network": network_io,
                "processes": process_count,
                "uptime": time.time() - psutil.boot_time()
            }
            
        except Exception as e:
            logger.error("Failed to get system metrics", error=str(e))
            return {}
    
    def update_metrics(self, request_time: float, status_code: int):
        """Update performance metrics"""
        if not self.enabled:
            return
        
        current_time = time.time()
        
        # Update request metrics
        self.metrics["requests_per_second"] = self._calculate_requests_per_second(current_time)
        self.metrics["avg_response_time"] = self._calculate_avg_response_time(request_time)
        self.metrics["error_rate"] = self._calculate_error_rate(status_code)
        
        # Update system metrics
        system_metrics = self.get_system_metrics()
        if system_metrics:
            self.metrics["cpu_usage"] = system_metrics.get("cpu", {}).get("usage_percent", 0)
            self.metrics["memory_usage"] = system_metrics.get("memory", {}).get("usage_percent", 0)
            self.metrics["disk_usage"] = system_metrics.get("disk", {}).get("usage_percent", 0)
        
        # Store in history
        self.performance_history.append({
            "timestamp": current_time,
            "request_time": request_time,
            "status_code": status_code,
            "cpu_usage": self.metrics["cpu_usage"],
            "memory_usage": self.metrics["memory_usage"]
        })
        
        # Trim history
        if len(self.performance_history) > self.max_history_size:
            self.performance_history = self.performance_history[-self.max_history_size:]
    
    def _calculate_requests_per_second(self, current_time: float) -> float:
        """Calculate requests per second"""
        if len(self.performance_history) < 2:
            return 0.0
        
        recent_requests = [
            entry for entry in self.performance_history[-60:]  # Last 60 entries
            if current_time - entry["timestamp"] <= 60  # Within last minute
        ]
        
        return len(recent_requests) / 60.0
    
    def _calculate_avg_response_time(self, request_time: float) -> float:
        """Calculate average response time"""
        if len(self.performance_history) < 2:
            return request_time
        
        recent_times = [entry["request_time"] for entry in self.performance_history[-100:]]
        recent_times.append(request_time)
        
        return sum(recent_times) / len(recent_times)
    
    def _calculate_error_rate(self, status_code: int) -> float:
        """Calculate error rate"""
        if len(self.performance_history) < 10:
            return 0.0 if status_code < 400 else 100.0
        
        recent_requests = self.performance_history[-100:]
        error_count = sum(1 for entry in recent_requests if entry["status_code"] >= 400)
        total_count = len(recent_requests) + 1
        
        return (error_count / total_count) * 100.0
    
    def check_performance_thresholds(self) -> List[Dict[str, Any]]:
        """Check if performance metrics exceed thresholds"""
        alerts = []
        
        # CPU threshold
        if self.metrics["cpu_usage"] > self.thresholds["cpu_usage"]:
            alerts.append({
                "metric": "cpu_usage",
                "current": self.metrics["cpu_usage"],
                "threshold": self.thresholds["cpu_usage"],
                "severity": "high" if self.metrics["cpu_usage"] > 95 else "medium",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Memory threshold
        if self.metrics["memory_usage"] > self.thresholds["memory_usage"]:
            alerts.append({
                "metric": "memory_usage",
                "current": self.metrics["memory_usage"],
                "threshold": self.thresholds["memory_usage"],
                "severity": "high" if self.metrics["memory_usage"] > 95 else "medium",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Disk threshold
        if self.metrics["disk_usage"] > self.thresholds["disk_usage"]:
            alerts.append({
                "metric": "disk_usage",
                "current": self.metrics["disk_usage"],
                "threshold": self.thresholds["disk_usage"],
                "severity": "critical" if self.metrics["disk_usage"] > 98 else "high",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Response time threshold
        if self.metrics["avg_response_time"] > self.thresholds["response_time"]:
            alerts.append({
                "metric": "response_time",
                "current": self.metrics["avg_response_time"],
                "threshold": self.thresholds["response_time"],
                "severity": "high" if self.metrics["avg_response_time"] > 1000 else "medium",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Error rate threshold
        if self.metrics["error_rate"] > self.thresholds["error_rate"]:
            alerts.append({
                "metric": "error_rate",
                "current": self.metrics["error_rate"],
                "threshold": self.thresholds["error_rate"],
                "severity": "critical" if self.metrics["error_rate"] > 10 else "high",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return alerts
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        # CPU recommendations
        if self.metrics["cpu_usage"] > 80:
            recommendations.append({
                "category": "cpu",
                "priority": "high" if self.metrics["cpu_usage"] > 95 else "medium",
                "recommendation": "Consider scaling horizontally or optimizing CPU-intensive operations",
                "current_value": self.metrics["cpu_usage"],
                "target_value": "< 80%"
            })
        
        # Memory recommendations
        if self.metrics["memory_usage"] > 85:
            recommendations.append({
                "category": "memory",
                "priority": "high" if self.metrics["memory_usage"] > 95 else "medium",
                "recommendation": "Check for memory leaks or increase available memory",
                "current_value": f"{self.metrics['memory_usage']:.1f}%",
                "target_value": "< 85%"
            })
        
        # Response time recommendations
        if self.metrics["avg_response_time"] > 500:
            recommendations.append({
                "category": "response_time",
                "priority": "high" if self.metrics["avg_response_time"] > 1000 else "medium",
                "recommendation": "Optimize database queries and enable caching",
                "current_value": f"{self.metrics['avg_response_time']:.1f}ms",
                "target_value": "< 500ms"
            })
        
        # Error rate recommendations
        if self.metrics["error_rate"] > 5:
            recommendations.append({
                "category": "error_rate",
                "priority": "critical" if self.metrics["error_rate"] > 10 else "high",
                "recommendation": "Investigate and fix application errors",
                "current_value": f"{self.metrics['error_rate']:.1f}%",
                "target_value": "< 5%"
            })
        
        return recommendations
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        return {
            "current_metrics": self.metrics,
            "thresholds": self.thresholds,
            "alerts": self.check_performance_thresholds(),
            "recommendations": self.get_optimization_recommendations(),
            "optimization_level": self.optimization_level,
            "enabled": self.enabled,
            "history_size": len(self.performance_history),
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def cleanup_old_metrics(self, max_age_hours: int = 24) -> int:
        """Clean up old performance metrics"""
        if not self.enabled:
            return 0
        
        cutoff_time = time.time() - (max_age_hours * 3600)
        original_size = len(self.performance_history)
        
        self.performance_history = [
            entry for entry in self.performance_history
            if entry["timestamp"] > cutoff_time
        ]
        
        cleaned_count = original_size - len(self.performance_history)
        
        if cleaned_count > 0:
            logger.info(
                "Performance metrics cleaned",
                cleaned_count=cleaned_count,
                remaining_count=len(self.performance_history)
            )
        
        return cleaned_count


# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()


def get_system_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    return performance_optimizer.get_system_metrics()


def update_performance_metrics(request_time: float, status_code: int):
    """Update performance metrics"""
    performance_optimizer.update_metrics(request_time, status_code)


def check_performance_thresholds() -> List[Dict[str, Any]]:
    """Check performance thresholds"""
    return performance_optimizer.check_performance_thresholds()


def get_optimization_recommendations() -> List[Dict[str, Any]]:
    """Get optimization recommendations"""
    return performance_optimizer.get_optimization_recommendations()


def get_performance_summary() -> Dict[str, Any]:
    """Get performance summary"""
    return performance_optimizer.get_performance_summary()


def cleanup_performance_metrics(max_age_hours: int = 24) -> int:
    """Clean up old performance metrics"""
    return performance_optimizer.cleanup_old_metrics(max_age_hours)
