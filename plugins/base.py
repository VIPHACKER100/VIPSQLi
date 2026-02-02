from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional, List, Any

class PluginBase(ABC):
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = True
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    def detect(self, url: str, response: Any) -> Tuple[bool, Optional[Dict]]:
        """
        Main detection logic
        Returns: (is_vulnerable, details_dict)
        """
        pass
    
    def supports_url(self, url: str) -> bool:
        """Override to filter applicable URLs"""
        return True
    
    def get_payloads(self) -> List[str]:
        """Override to provide test payloads"""
        return []
