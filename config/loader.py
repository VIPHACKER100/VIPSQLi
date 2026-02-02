import yaml
from pathlib import Path
from typing import Dict, Any

class ConfigLoader:
    def __init__(self, profile: str = "balanced"):
        self.profile = profile
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        base = self._load_yaml("default.yaml")
        if self.profile and self.profile != "default":
             try:
                profile_config = self._load_yaml(f"profiles/{self.profile}.yaml")
                base = self._merge(base, profile_config)
             except FileNotFoundError:
                 pass # Fallback to default if profile not found
        return base
    
    def _load_yaml(self, filename: str) -> Dict:
        path = Path(__file__).parent / filename
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _merge(self, base: Dict, override: Dict) -> Dict:
        result = base.copy()
        for key, value in override.items():
            if isinstance(value, dict) and key in result:
                result[key] = self._merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key: str, default=None):
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default
