import importlib.util
import sys
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Any, Set, Callable
from collections import defaultdict
from datetime import datetime
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import PluginBase, PluginStatus, PluginPriority, DetectionResult
from utils.logger import get_logger

logger = get_logger("vipsqli.plugins")


class PluginEvent:
    """Event system for plugin communication"""
    def __init__(self, name: str, data: Any = None, source: Optional[str] = None):
        self.name = name
        self.data = data
        self.source = source
        self.timestamp = datetime.now()


class PluginManager:
    """Enhanced plugin manager with advanced features"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.plugins: List[PluginBase] = []
        self._plugin_map: Dict[str, PluginBase] = {}
        self._event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._dependency_graph: Dict[str, Set[str]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=config.get('plugins', {}).get('max_workers', 10)
        )
        self._health_check_thread = None
        self._health_check_running = False
        self._plugin_cache: Dict[str, Any] = {}
        
    def discover_plugins(self, additional_dirs: Optional[List[str]] = None) -> List[str]:
        """Discover plugins from multiple directories"""
        plugin_dirs = [
            Path(__file__).parent / "builtin",
            Path.home() / ".vipsqli" / "plugins"
        ]
        
        # Add additional directories from config
        if self.config.get('plugins', {}).get('directories'):
            plugin_dirs.extend([Path(d) for d in self.config['plugins']['directories']])
        
        # Add runtime-provided directories
        if additional_dirs:
            plugin_dirs.extend([Path(d) for d in additional_dirs])
        
        files = []
        for dir_path in plugin_dirs:
            if dir_path.exists():
                logger.debug(f"Scanning plugin directory: {dir_path}")
                files.extend(dir_path.glob("*.py"))
        
        # Filter out private modules and duplicates
        unique_files = {}
        for f in files:
            if not f.name.startswith("_"):
                unique_files[f.stem] = str(f)
        
        logger.info(f"Discovered {len(unique_files)} plugin files")
        return list(unique_files.values())
    
    def load_plugin(self, path: str) -> Optional[PluginBase]:
        """Load a single plugin with validation"""
        try:
            # Check cache first
            if path in self._plugin_cache:
                cached_time, plugin_class = self._plugin_cache[path]
                # Cache validity: 5 minutes
                if time.time() - cached_time < 300:
                    return plugin_class(self.config)
            
            spec = importlib.util.spec_from_file_location("plugin_module", path)
            if not spec or not spec.loader:
                logger.error(f"Invalid plugin specification: {path}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, PluginBase) and obj != PluginBase:
                    plugin_class = obj
                    break
            
            if not plugin_class:
                logger.warning(f"No valid plugin class found in {path}")
                return None
            
            # Instantiate and validate
            plugin = plugin_class(self.config)
            
            # Validate configuration
            is_valid, errors = plugin.validate_config()
            if not is_valid:
                logger.error(f"Plugin {plugin.name} config validation failed: {errors}")
                return None
            
            # Initialize plugin
            if not plugin.initialize():
                logger.error(f"Plugin {plugin.name} initialization failed")
                return None
            
            # Cache the plugin class
            self._plugin_cache[path] = (time.time(), plugin_class)
            
            logger.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
            return plugin
            
        except Exception as e:
            logger.error(f"Failed to load plugin {path}: {e}", exc_info=True)
            return None
    
    def load_all_plugins(self):
        """Load all discovered plugins with dependency resolution"""
        if not self.config.get('plugins', {}).get('enabled', True):
            logger.info("Plugins are disabled in configuration")
            return
        
        # Discover plugins
        plugin_paths = self.discover_plugins()
        
        # Load plugins
        loaded_plugins = []
        for path in plugin_paths:
            plugin = self.load_plugin(path)
            if plugin:
                loaded_plugins.append(plugin)
        
        # Build dependency graph
        self._build_dependency_graph(loaded_plugins)
        
        # Resolve dependencies and sort by priority
        sorted_plugins = self._resolve_dependencies(loaded_plugins)
        
        # Store plugins
        self.plugins = sorted_plugins
        self._plugin_map = {p.name: p for p in self.plugins}
        
        logger.info(f"Loaded {len(self.plugins)} plugins successfully")
        
        # Start health check thread if enabled
        if self.config.get('plugins', {}).get('health_checks', True):
            self.start_health_checks()
    
    def _build_dependency_graph(self, plugins: List[PluginBase]):
        """Build plugin dependency graph"""
        for plugin in plugins:
            deps = set(plugin.metadata.dependencies)
            self._dependency_graph[plugin.name] = deps
    
    def _resolve_dependencies(self, plugins: List[PluginBase]) -> List[PluginBase]:
        """Resolve dependencies and sort plugins by priority"""
        # Check for missing dependencies
        available_plugins = {p.name for p in plugins}
        
        for plugin in plugins:
            missing_deps = self._dependency_graph.get(plugin.name, set()) - available_plugins
            if missing_deps:
                logger.warning(
                    f"Plugin {plugin.name} has missing dependencies: {missing_deps}"
                )
        
        # Sort by priority (lower number = higher priority)
        sorted_plugins = sorted(
            plugins,
            key=lambda p: p.metadata.priority.value
        )
        
        return sorted_plugins
    
    def run_plugins(self, url: str, response: Any, 
                   parallel: bool = True) -> Dict[str, Any]:
        """
        Run plugins with optional parallel execution
        """
        results = {}
        
        if not self.plugins:
            return results
        
        # Filter applicable plugins
        applicable_plugins = [
            p for p in self.plugins 
            if p.enabled and p.status == PluginStatus.READY and p.supports_url(url)
        ]
        
        if not applicable_plugins:
            logger.debug(f"No applicable plugins for URL: {url}")
            return results
        
        logger.debug(f"Running {len(applicable_plugins)} plugins for {url}")
        
        if parallel and len(applicable_plugins) > 1:
            results = self._run_plugins_parallel(applicable_plugins, url, response)
        else:
            results = self._run_plugins_sequential(applicable_plugins, url, response)
        
        return results
    
    def _run_plugins_sequential(self, plugins: List[PluginBase], 
                               url: str, response: Any) -> Dict[str, Any]:
        """Run plugins sequentially"""
        results = {}
        
        for plugin in plugins:
            plugin_result = self._execute_plugin(plugin, url, response)
            results[plugin.name] = plugin_result
        
        return results
    
    def _run_plugins_parallel(self, plugins: List[PluginBase], 
                             url: str, response: Any) -> Dict[str, Any]:
        """Run plugins in parallel using thread pool"""
        results = {}
        
        future_to_plugin = {
            self._executor.submit(self._execute_plugin, plugin, url, response): plugin
            for plugin in plugins
        }
        
        for future in as_completed(future_to_plugin):
            plugin = future_to_plugin[future]
            try:
                result = future.result(timeout=30)  # 30 second timeout
                results[plugin.name] = result
            except Exception as e:
                logger.error(f"Plugin {plugin.name} execution failed: {e}")
                results[plugin.name] = {'error': str(e), 'vulnerable': False}
        
        return results
    
    def _execute_plugin(self, plugin: PluginBase, url: str, response: Any) -> Dict[str, Any]:
        """Execute a single plugin with metrics and error handling"""
        start_time = time.time()
        plugin.status = PluginStatus.RUNNING
        
        try:
            is_vuln, details = plugin.detect(url, response)
            execution_time = time.time() - start_time
            
            plugin.update_metrics(execution_time, True, is_vuln)
            plugin.status = PluginStatus.READY
            
            if is_vuln:
                self.emit_event(PluginEvent(
                    name='vulnerability_detected',
                    data={'plugin': plugin.name, 'url': url, 'details': details},
                    source=plugin.name
                ))
                
                return {
                    'vulnerable': True,
                    'details': details,
                    'execution_time': execution_time,
                    'plugin_version': plugin.version
                }
            else:
                return {
                    'vulnerable': False,
                    'execution_time': execution_time
                }
                
        except Exception as e:
            execution_time = time.time() - start_time
            plugin.update_metrics(execution_time, False, False)
            plugin.status = PluginStatus.ERROR
            
            logger.error(f"Error running plugin {plugin.name}: {e}", exc_info=True)
            
            self.emit_event(PluginEvent(
                name='plugin_error',
                data={'plugin': plugin.name, 'error': str(e)},
                source=plugin.name
            ))
            
            return {
                'error': str(e),
                'vulnerable': False,
                'execution_time': execution_time
            }
    
    async def run_plugins_async(self, url: str, response: Any) -> Dict[str, DetectionResult]:
        """Run plugins asynchronously"""
        results = {}
        
        applicable_plugins = [
            p for p in self.plugins 
            if p.enabled and p.status == PluginStatus.READY and p.supports_url(url)
        ]
        
        tasks = [
            plugin.detect_async(url, response)
            for plugin in applicable_plugins
        ]
        
        plugin_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for plugin, result in zip(applicable_plugins, plugin_results):
            if isinstance(result, Exception):
                logger.error(f"Async plugin {plugin.name} failed: {result}")
                results[plugin.name] = DetectionResult(
                    vulnerable=False,
                    details={'error': str(result)}
                )
            else:
                results[plugin.name] = result
        
        return results
    
    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Get plugin by name"""
        return self._plugin_map.get(name)
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = True
            logger.info(f"Enabled plugin: {name}")
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = False
            plugin.status = PluginStatus.DISABLED
            logger.info(f"Disabled plugin: {name}")
            return True
        return False
    
    def reload_plugin(self, name: str) -> bool:
        """Reload a single plugin"""
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        
        # Find the original path
        for path in self.discover_plugins():
            try:
                new_plugin = self.load_plugin(path)
                if new_plugin and new_plugin.name == name:
                    # Replace in list
                    idx = self.plugins.index(plugin)
                    plugin.cleanup()
                    self.plugins[idx] = new_plugin
                    self._plugin_map[name] = new_plugin
                    logger.info(f"Reloaded plugin: {name}")
                    return True
            except Exception as e:
                logger.error(f"Failed to reload plugin {name}: {e}")
                return False
        
        return False
    
    def start_health_checks(self, interval: int = 60):
        """Start background health check thread"""
        if self._health_check_running:
            return
        
        def health_check_loop():
            while self._health_check_running:
                self.check_all_plugins_health()
                time.sleep(interval)
        
        self._health_check_running = True
        self._health_check_thread = threading.Thread(
            target=health_check_loop,
            daemon=True
        )
        self._health_check_thread.start()
        logger.info("Health check thread started")
    
    def stop_health_checks(self):
        """Stop background health check thread"""
        self._health_check_running = False
        if self._health_check_thread:
            self._health_check_thread.join(timeout=5)
        logger.info("Health check thread stopped")
    
    def check_all_plugins_health(self):
        """Run health checks on all plugins"""
        for plugin in self.plugins:
            is_healthy, error = plugin.health_check()
            if not is_healthy:
                logger.warning(
                    f"Plugin {plugin.name} health check failed: {error}"
                )
                plugin.status = PluginStatus.ERROR
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all plugins"""
        return {
            plugin.name: plugin.get_metrics()
            for plugin in self.plugins
        }
    
    def on_event(self, event_name: str, handler: Callable[[PluginEvent], None]):
        """Register event handler"""
        self._event_handlers[event_name].append(handler)
    
    def emit_event(self, event: PluginEvent):
        """Emit event to registered handlers"""
        for handler in self._event_handlers.get(event.name, []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
    
    def cleanup(self):
        """Cleanup all plugins and manager resources"""
        logger.info("Cleaning up plugin manager")
        
        # Stop health checks
        self.stop_health_checks()
        
        # Cleanup all plugins
        for plugin in self.plugins:
            try:
                plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin {plugin.name}: {e}")
        
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        self.plugins.clear()
        self._plugin_map.clear()
        
        logger.info("Plugin manager cleanup complete")
    
    def __repr__(self) -> str:
        return f"<PluginManager plugins={len(self.plugins)} enabled={len([p for p in self.plugins if p.enabled])}>"
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.cleanup()