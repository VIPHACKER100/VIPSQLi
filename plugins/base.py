from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional, List, Any, Set
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime


class PluginStatus(Enum):
    """Plugin lifecycle states"""
    UNLOADED = "unloaded"
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


class PluginPriority(Enum):
    """Plugin execution priority"""
    CRITICAL = 0
    HIGH = 10
    NORMAL = 50
    LOW = 100


@dataclass
class PluginMetadata:
    """Plugin metadata and information"""
    name: str
    version: str
    author: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    priority: PluginPriority = PluginPriority.NORMAL
    tags: List[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    """Standardized detection result"""
    vulnerable: bool
    severity: str = "unknown"  # critical, high, medium, low, info
    confidence: float = 1.0  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class PluginBase(ABC):
    """Enhanced base class for all plugins"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = True
        self.status = PluginStatus.UNLOADED
        self._health_check_interval = config.get('health_check_interval', 60)
        self._last_health_check = None
        self._execution_count = 0
        self._error_count = 0
        self._metrics = {
            'total_executions': 0,
            'successful_detections': 0,
            'failed_executions': 0,
            'average_execution_time': 0.0
        }
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Plugin metadata"""
        pass
    
    # Backward compatibility
    @property
    def name(self) -> str:
        return self.metadata.name
    
    @property
    def version(self) -> str:
        return self.metadata.version
    
    @abstractmethod
    def detect(self, url: str, response: Any) -> Tuple[bool, Optional[Dict]]:
        """
        Main detection logic (synchronous)
        Returns: (is_vulnerable, details_dict)
        
        NOTE: Consider implementing detect_async for better performance
        """
        pass
    
    async def detect_async(self, url: str, response: Any) -> DetectionResult:
        """
        Async detection logic with structured results
        Override this for async plugins
        """
        is_vuln, details = self.detect(url, response)
        return DetectionResult(
            vulnerable=is_vuln,
            details=details or {}
        )
    
    def initialize(self) -> bool:
        """
        Plugin initialization hook
        Called once when plugin is loaded
        Returns: True if successful, False otherwise
        """
        self.status = PluginStatus.INITIALIZING
        try:
            self._on_initialize()
            self.status = PluginStatus.READY
            return True
        except Exception as e:
            self.status = PluginStatus.ERROR
            raise
    
    def _on_initialize(self):
        """Override this for custom initialization logic"""
        pass
    
    def cleanup(self):
        """
        Plugin cleanup hook
        Called when plugin is unloaded or disabled
        """
        try:
            self._on_cleanup()
        finally:
            self.status = PluginStatus.UNLOADED
    
    def _on_cleanup(self):
        """Override this for custom cleanup logic"""
        pass
    
    def health_check(self) -> Tuple[bool, Optional[str]]:
        """
        Plugin health check
        Returns: (is_healthy, error_message)
        """
        self._last_health_check = datetime.now()
        try:
            return self._perform_health_check()
        except Exception as e:
            return False, f"Health check failed: {str(e)}"
    
    def _perform_health_check(self) -> Tuple[bool, Optional[str]]:
        """Override this for custom health check logic"""
        return True, None
    
    def supports_url(self, url: str) -> bool:
        """Override to filter applicable URLs"""
        return True
    
    def get_payloads(self) -> List[str]:
        """Override to provide test payloads"""
        return []
    
    def get_supported_methods(self) -> Set[str]:
        """HTTP methods this plugin supports"""
        return {"GET", "POST", "PUT", "DELETE", "PATCH"}
    
    def get_required_headers(self) -> Dict[str, str]:
        """Headers required for this plugin to work"""
        return {}
    
    def update_metrics(self, execution_time: float, success: bool, detected: bool):
        """Update plugin metrics"""
        self._execution_count += 1
        self._metrics['total_executions'] += 1
        
        if success:
            if detected:
                self._metrics['successful_detections'] += 1
        else:
            self._error_count += 1
            self._metrics['failed_executions'] += 1
        
        # Update average execution time
        current_avg = self._metrics['average_execution_time']
        total = self._metrics['total_executions']
        self._metrics['average_execution_time'] = (
            (current_avg * (total - 1) + execution_time) / total
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get plugin performance metrics"""
        return {
            **self._metrics,
            'error_rate': self._error_count / max(self._execution_count, 1),
            'status': self.status.value,
            'last_health_check': self._last_health_check
        }
    
    def reload_config(self, new_config: Dict):
        """
        Hot-reload configuration
        Override _on_config_reload for custom logic
        """
        old_config = self.config
        self.config = new_config
        try:
            self._on_config_reload(old_config, new_config)
        except Exception as e:
            self.config = old_config
            raise
    
    def _on_config_reload(self, old_config: Dict, new_config: Dict):
        """Override this for custom config reload logic"""
        pass
    
    def validate_config(self) -> Tuple[bool, List[str]]:
        """
        Validate plugin configuration
        Returns: (is_valid, error_messages)
        """
        errors = []
        return len(errors) == 0, errors
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} version={self.version} status={self.status.value}>"