import importlib.util
import sys
from pathlib import Path
from typing import List, Dict, Optional, Any
from .base import PluginBase
from utils.logger import get_logger

logger = get_logger("vipsqli.plugins")

class PluginManager:
    def __init__(self, config: Dict):
        self.config = config
        self.plugins: List[PluginBase] = []
    
    def discover_plugins(self) -> List[str]:
        plugin_dirs = [
            Path(__file__).parent / "builtin",
            Path.home() / ".vipsqli" / "plugins"
        ]
        
        files = []
        for dir_path in plugin_dirs:
            if dir_path.exists():
                files.extend(dir_path.glob("*.py"))
        return [str(f) for f in files if not f.name.startswith("_")]
    
    def load_plugin(self, path: str) -> Optional[PluginBase]:
        try:
            spec = importlib.util.spec_from_file_location("plugin_module", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, PluginBase) and obj != PluginBase:
                    logger.debug(f"Loaded plugin: {obj(self.config).name}")
                    return obj(self.config)
            return None
        except Exception as e:
            logger.error(f"Failed to load plugin {path}: {e}")
            return None
    
    def load_all_plugins(self):
        if not self.config.get('plugins', {}).get('enabled', True):
            return
        
        for path in self.discover_plugins():
            plugin = self.load_plugin(path)
            if plugin:
                self.plugins.append(plugin)
        
        logger.info(f"Loaded {len(self.plugins)} plugins")
    
    def run_plugins(self, url: str, response: Any) -> Dict[str, Any]:
        results = {}
        for plugin in self.plugins:
            if not plugin.supports_url(url):
                continue
            
            try:
                is_vuln, details = plugin.detect(url, response)
                if is_vuln:
                    results[plugin.name] = {'vulnerable': True, 'details': details}
            except Exception as e:
                logger.error(f"Error running plugin {plugin.name}: {e}")
                results[plugin.name] = {'error': str(e)}
        
        return results
