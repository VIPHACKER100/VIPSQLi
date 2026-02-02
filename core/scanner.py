from typing import Dict, Optional, List, Tuple, Any, Callable
import requests
import random
import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from utils.logger import get_logger
from utils.rate_limiter import AdaptiveRateLimiter
from plugins.manager import PluginManager

logger = get_logger("vipsqli.core")


class ScanStatus(Enum):
    """Scan result status"""
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    SAFE = "SAFE"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"


class ProxyHealth(Enum):
    """Proxy health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class ProxyInfo:
    """Proxy information with health tracking"""
    url: str
    protocol: str = "http"
    health: ProxyHealth = ProxyHealth.UNKNOWN
    success_count: int = 0
    failure_count: int = 0
    last_used: float = 0.0
    avg_response_time: float = 0.0
    consecutive_failures: int = 0
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0
    
    @property
    def is_available(self) -> bool:
        return (self.health != ProxyHealth.FAILED and 
                self.consecutive_failures < 5)


@dataclass
class ScanResult:
    """Comprehensive scan result"""
    url: str
    status: ScanStatus
    confidence: float = 0.0
    
    # Detection results
    error_based: Optional[Dict] = None
    union_based: Optional[Dict] = None
    boolean_based: Optional[Dict] = None
    time_based: Optional[Dict] = None
    stacked_queries: Optional[Dict] = None
    
    # Additional info
    waf_detected: bool = False
    waf_name: Optional[str] = None
    waf_confidence: float = 0.0
    waf_bypass_suggestions: List[str] = field(default_factory=list)
    
    # ML predictions
    ml_confidence: float = 0.0
    ml_features: Optional[Dict] = None
    
    # Plugin results
    plugin_results: Dict = field(default_factory=dict)
    
    # Response info
    response_time: float = 0.0
    status_code: Optional[int] = None
    content_length: int = 0
    
    # Metadata
    timestamp: float = field(default_factory=time.time)
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_score: float = 0.0
    severity: str = "LOW"
    summary: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'url': self.url,
            'status': self.status.value,
            'confidence': self.confidence,
            'waf_detected': self.waf_detected,
            'waf_name': self.waf_name,
            'waf_confidence': self.waf_confidence,
            'ml_confidence': self.ml_confidence,
            'response_time': self.response_time,
            'status_code': self.status_code,
            'risk_score': self.risk_score,
            'severity': self.severity,
            'summary': self.summary,
            'timestamp': self.timestamp,
            'errors': self.errors,
            'warnings': self.warnings,
            'detections': {
                'error_based': self.error_based,
                'union_based': self.union_based,
                'boolean_based': self.boolean_based,
                'time_based': self.time_based,
                'stacked_queries': self.stacked_queries,
            },
            'plugins': self.plugin_results
        }

    def to_dashboard_dict(self) -> Dict:
        """Convert to dictionary format expected by the dashboard"""
        return {
            'vulnerable': self.status == ScanStatus.VULNERABLE,
            'risk': self.severity,
            'details': self.summary or "No details available",
            'payload': self.url,  # The dashboard uses payload_used which it gets from result.get('payload')
            'status_code': self.status_code,
            'response_time': self.response_time,
            'ml_confidence': self.ml_confidence,
            'ml_prediction': "Malicious" if self.ml_confidence > 0.5 else "Safe",
            'metadata': {
                'waf_detected': self.waf_detected,
                'waf_name': self.waf_name,
                'content_length': self.content_length,
                'confidence': self.confidence
            },
            'errors': self.errors + self.warnings
        }


class URLScanner:
    """
    Advanced URL Scanner with multiple detection methods
    
    Features:
    - Async and sync scanning
    - Smart proxy rotation with health tracking
    - ML-enhanced detection
    - Plugin system integration
    - Comprehensive error handling
    - Rate limiting and retry logic
    - WAF detection and bypass
    - Result caching
    - Batch scanning support
    """
    
    def __init__(
        self, 
        config: Dict, 
        plugin_manager: Optional[PluginManager] = None,
        ml_detector: Optional[Any] = None
    ):
        self.config = config
        scanner_config = config.get('scanner', {})
        
        # Basic settings
        self.user_agent = scanner_config.get('user_agent', 'VIPSQLi/3.0')
        self.timeout = scanner_config.get('timeout', 10)
        self.max_retries = scanner_config.get('max_retries', 3)
        self.retry_delay = scanner_config.get('retry_delay', 1.0)
        self.verify_ssl = scanner_config.get('verify_ssl', True)
        
        # Advanced settings
        self.max_redirects = scanner_config.get('max_redirects', 5)
        self.max_workers = scanner_config.get('max_workers', 10)
        self.cache_enabled = scanner_config.get('cache_enabled', True)
        self.cache_ttl = scanner_config.get('cache_ttl', 3600)  # 1 hour
        
        # Session setup
        self.session = requests.Session()
        self._setup_session()
        
        # Proxy management
        self.proxies: List[ProxyInfo] = []
        self.proxy_rotation_enabled = scanner_config.get('proxy_rotation', False)
        
        # Components
        self.rate_limiter = AdaptiveRateLimiter(config)
        self.plugin_manager = plugin_manager or PluginManager(config)
        self.plugin_manager.load_all_plugins()
        self.ml_detector = ml_detector
        
        # Caching
        self._cache: Dict[str, Tuple[ScanResult, float]] = {}
        
        # Statistics
        self.stats = defaultdict(int)
        self.scan_history: List[ScanResult] = []
        
        # Thread pool for batch operations
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        logger.info(f"URLScanner initialized with {self.max_workers} workers")
    
    def _setup_session(self):
        """Configure session with optimal settings"""
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure adapters for connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=50,
            max_retries=0  # We handle retries manually
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def set_proxies(self, proxies: List[str]):
        """Set proxy list with automatic health tracking"""
        self.proxies = []
        for proxy_url in proxies:
            protocol = 'https' if proxy_url.startswith('https') else 'http'
            self.proxies.append(ProxyInfo(url=proxy_url, protocol=protocol))
        logger.info(f"Loaded {len(self.proxies)} proxies")
    
    def _get_best_proxy(self) -> Optional[Dict]:
        """Select best available proxy based on health metrics"""
        if not self.proxies or not self.proxy_rotation_enabled:
            return None
        
        # Filter available proxies
        available = [p for p in self.proxies if p.is_available]
        if not available:
            # Reset all if none available
            for p in self.proxies:
                p.consecutive_failures = 0
                p.health = ProxyHealth.UNKNOWN
            available = self.proxies
        
        # Sort by success rate and response time
        available.sort(
            key=lambda p: (p.success_rate, -p.avg_response_time),
            reverse=True
        )
        
        # Select from top performers with some randomness
        top_proxies = available[:max(3, len(available) // 3)]
        selected = random.choice(top_proxies)
        selected.last_used = time.time()
        
        return {
            "http": selected.url,
            "https": selected.url
        }
    
    def _update_proxy_health(
        self, 
        proxy_dict: Optional[Dict], 
        success: bool, 
        response_time: float = 0.0
    ):
        """Update proxy health metrics"""
        if not proxy_dict:
            return
        
        proxy_url = proxy_dict.get('http') or proxy_dict.get('https')
        proxy_info = next((p for p in self.proxies if p.url == proxy_url), None)
        
        if proxy_info:
            if success:
                proxy_info.success_count += 1
                proxy_info.consecutive_failures = 0
                # Update average response time
                if proxy_info.avg_response_time > 0:
                    proxy_info.avg_response_time = (
                        proxy_info.avg_response_time * 0.7 + response_time * 0.3
                    )
                else:
                    proxy_info.avg_response_time = response_time
                
                # Update health status
                if proxy_info.success_rate >= 0.9:
                    proxy_info.health = ProxyHealth.HEALTHY
                elif proxy_info.success_rate >= 0.7:
                    proxy_info.health = ProxyHealth.DEGRADED
            else:
                proxy_info.failure_count += 1
                proxy_info.consecutive_failures += 1
                
                # Mark as failed if too many consecutive failures
                if proxy_info.consecutive_failures >= 5:
                    proxy_info.health = ProxyHealth.FAILED
                elif proxy_info.success_rate < 0.5:
                    proxy_info.health = ProxyHealth.DEGRADED
    
    def _get_cache_key(self, url: str, method: str = 'GET') -> str:
        """Generate cache key for URL"""
        return hashlib.md5(f"{method}:{url}".encode()).hexdigest()
    
    def _get_cached_result(self, url: str) -> Optional[ScanResult]:
        """Get cached scan result if valid"""
        if not self.cache_enabled:
            return None
        
        cache_key = self._get_cache_key(url)
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                logger.debug(f"Cache hit for {url}")
                self.stats['cache_hits'] += 1
                return result
            else:
                # Expired
                del self._cache[cache_key]
        
        self.stats['cache_misses'] += 1
        return None
    
    def _cache_result(self, url: str, result: ScanResult):
        """Cache scan result"""
        if not self.cache_enabled:
            return
        
        cache_key = self._get_cache_key(url)
        self._cache[cache_key] = (result, time.time())
        
        # Prune old entries if cache is too large
        if len(self._cache) > 1000:
            current_time = time.time()
            expired = [
                k for k, (_, ts) in self._cache.items()
                if current_time - ts > self.cache_ttl
            ]
            for k in expired:
                del self._cache[k]
    
    def fetch_url(
        self, 
        url: str, 
        method: str = 'GET',
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retry_count: int = 0
    ) -> Optional[requests.Response]:
        """
        Fetch URL with comprehensive error handling and retry logic
        """
        self.rate_limiter.acquire()
        
        proxy = self._get_best_proxy()
        custom_headers = self.session.headers.copy()
        if headers:
            custom_headers.update(headers)
        
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=custom_headers,
                timeout=self.timeout,
                proxies=proxy,
                allow_redirects=True,
                verify=self.verify_ssl
            )
            
            elapsed = time.time() - start_time
            
            # Update proxy health
            self._update_proxy_health(proxy, True, elapsed)
            
            # Report to rate limiter
            if response.status_code in [429, 503]:
                self.rate_limiter.report_error(response.status_code)
                
                # Retry with backoff
                if retry_count < self.max_retries:
                    delay = self.retry_delay * (2 ** retry_count)
                    logger.warning(
                        f"Rate limited ({response.status_code}), "
                        f"retrying in {delay}s (attempt {retry_count + 1}/{self.max_retries})"
                    )
                    time.sleep(delay)
                    return self.fetch_url(url, method, params, data, headers, retry_count + 1)
            else:
                self.rate_limiter.report_success()
            
            self.stats['requests_success'] += 1
            return response
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            self.stats['requests_timeout'] += 1
            self._update_proxy_health(proxy, False)
            
            # Retry on timeout
            if retry_count < self.max_retries:
                time.sleep(self.retry_delay)
                return self.fetch_url(url, method, params, data, headers, retry_count + 1)
            return None
            
        except requests.exceptions.ProxyError:
            logger.warning(f"Proxy error for {url}")
            self.stats['requests_proxy_error'] += 1
            self._update_proxy_health(proxy, False)
            
            # Retry with different proxy
            if retry_count < self.max_retries:
                return self.fetch_url(url, method, params, data, headers, retry_count + 1)
            return None
            
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {url}")
            self.stats['requests_connection_error'] += 1
            self._update_proxy_health(proxy, False)
            
            if retry_count < self.max_retries:
                time.sleep(self.retry_delay * 2)
                return self.fetch_url(url, method, params, data, headers, retry_count + 1)
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            self.stats['requests_error'] += 1
            self._update_proxy_health(proxy, False)
            return None
    
    async def fetch_url_async(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Optional[Tuple[int, str, Dict, float]]:
        """
        Async version of fetch_url
        Returns: (status_code, text, headers, elapsed_time) or None
        """
        proxy = self._get_best_proxy()
        proxy_url = proxy.get('http') if proxy else None
        
        custom_headers = dict(self.session.headers)
        if headers:
            custom_headers.update(headers)
        
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=custom_headers,
                    proxy=proxy_url,
                    ssl=self.verify_ssl
                ) as response:
                    text = await response.text()
                    elapsed = time.time() - start_time
                    
                    self._update_proxy_health(proxy, True, elapsed)
                    self.stats['requests_success'] += 1
                    
                    return (
                        response.status,
                        text,
                        dict(response.headers),
                        elapsed
                    )
                    
        except asyncio.TimeoutError:
            logger.warning(f"Async timeout for {url}")
            self.stats['requests_timeout'] += 1
            self._update_proxy_health(proxy, False)
            return None
            
        except Exception as e:
            logger.error(f"Async error for {url}: {e}")
            self.stats['requests_error'] += 1
            self._update_proxy_health(proxy, False)
            return None
    
    def is_static_file(self, url: str) -> bool:
        """Check if URL points to static resource"""
        static_extensions = (
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.pdf', 
            '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', 
            '.mp4', '.mp3', '.avi', '.mov', '.zip', '.rar', 
            '.tar', '.gz', '.7z', '.xml', '.json', '.txt'
        )
        
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in static_extensions)
    
    def is_valid_target(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate if URL is a valid scan target
        Returns: (is_valid, reason)
        """
        # Check static file
        if self.is_static_file(url):
            return False, "Static file"
        
        # Check for parameters
        parsed = urlparse(url)
        if not parsed.query:
            return False, "No parameters"
        
        # Check for common login/logout pages
        exclusion_patterns = [
            r'/logout', r'/signout', r'/exit',
            r'/admin/login', r'/user/login',
        ]
        
        path_lower = parsed.path.lower()
        for pattern in exclusion_patterns:
            if re.search(pattern, path_lower):
                return False, f"Excluded pattern: {pattern}"
        
        return True, None
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract and parse query parameters"""
        return parse_qs(urlparse(url).query)
    
    def inject_payloads(
        self, 
        url: str, 
        payloads: List[str],
        param_name: Optional[str] = None
    ) -> List[str]:
        """
        Generate URLs with injected payloads
        
        Args:
            url: Base URL
            payloads: List of SQLi payloads
            param_name: Specific parameter to inject (None = all parameters)
        
        Returns:
            List of URLs with payloads injected
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return []
        
        injected_urls = []
        target_params = [param_name] if param_name else list(params.keys())
        
        for payload in payloads:
            for param in target_params:
                if param in params:
                    # Create modified params
                    modified_params = params.copy()
                    original_value = params[param][0] if params[param] else ''
                    
                    # Inject payload
                    modified_params[param] = [f"{original_value}{payload}"]
                    
                    # Build new URL
                    new_query = urlencode(modified_params, doseq=True)
                    new_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    
                    injected_urls.append(new_url)
        
        return injected_urls
    
    def scan_url(
        self, 
        url: str,
        use_ml: bool = True,
        run_plugins: bool = True,
        payloads: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Comprehensive URL scan with all detection methods
        
        Args:
            url: Target URL
            use_ml: Use ML detection
            run_plugins: Run plugin checks
            payloads: Custom payloads (None = use defaults)
        
        Returns:
            ScanResult object with comprehensive results
        """
        scan_start = time.time()
        self.stats['scans_total'] += 1
        
        # Check cache
        if cached := self._get_cached_result(url):
            self.stats['scans_cached'] += 1
            return cached
        
        # Initialize result
        result = ScanResult(url=url, status=ScanStatus.SAFE)
        
        # Validate target
        is_valid, reason = self.is_valid_target(url)
        if not is_valid:
            result.status = ScanStatus.ERROR
            result.errors.append(f"Invalid target: {reason}")
            return result
        
        # Fetch URL
        response = self.fetch_url(url)
        if not response:
            result.status = ScanStatus.ERROR
            result.errors.append("Failed to fetch URL")
            self.stats['scans_failed'] += 1
            return result
        
        # Populate response info
        result.status_code = response.status_code
        result.content_length = len(response.content)
        result.response_time = response.elapsed.total_seconds()
        
        # Import detector
        try:
            from core.detector import AdvancedSQLiDetector
        except ImportError:
            # Fallback if module naming is different
            from core.detector import SQLiDetector as AdvancedSQLiDetector
        
        # Run comprehensive detection
        detector = AdvancedSQLiDetector(self.config)
        
        detection_results = detector.comprehensive_scan(
            response_text=response.text,
            response_headers=dict(response.headers),
            payload=url,
            elapsed_time=result.response_time,
            status_code=response.status_code,
            cookies=dict(response.cookies) if hasattr(response, 'cookies') else None
        )
        
        # Process detection results
        if detection_results['detections']:
            result.status = ScanStatus.VULNERABLE
            result.confidence = detection_results.get('risk_score', 0.8)
            result.risk_score = detection_results['risk_score']
            
            # Map detections to result
            for detection in detection_results['detections']:
                detection_type = detection.sqli_type.value
                detection_data = {
                    'confidence': detection.confidence,
                    'severity': detection.severity.name,
                    'indicators': detection.indicators,
                    'context': detection.context,
                    'remediation': detection.remediation
                }
                
                if 'error' in detection_type:
                    result.error_based = detection_data
                elif 'union' in detection_type:
                    result.union_based = detection_data
                elif 'boolean' in detection_type:
                    result.boolean_based = detection_data
                elif 'time' in detection_type:
                    result.time_based = detection_data
                elif 'stacked' in detection_type:
                    result.stacked_queries = detection_data
            
            # Determine severity
            max_severity = max(d.severity.value for d in detection_results['detections'])
            if max_severity >= 4:
                result.severity = "CRITICAL"
            elif max_severity >= 3:
                result.severity = "HIGH"
            elif max_severity >= 2:
                result.severity = "MEDIUM"
            else:
                result.severity = "LOW"
        
        # WAF detection
        if detection_results['waf'].detected:
            result.waf_detected = True
            result.waf_name = detection_results['waf'].waf_name
            result.waf_confidence = detection_results['waf'].confidence
            result.waf_bypass_suggestions = detection_results['waf'].bypass_suggestions
            
            if not result.status == ScanStatus.VULNERABLE:
                result.status = ScanStatus.BLOCKED
                result.warnings.append(f"WAF detected: {result.waf_name}")
        
        # ML detection
        if use_ml and self.ml_detector:
            try:
                from ml.features import FeatureExtractor
                extractor = FeatureExtractor()
                
                # Extract features
                features = extractor.combine_features(
                    url, 
                    response, 
                    {
                        'errors': detection_results.get('detections', []),
                        'waf': result.waf_detected
                    }
                )
                
                # Predict
                is_vuln_ml, ml_confidence = self.ml_detector.predict(features)
                result.ml_confidence = float(ml_confidence)
                result.ml_features = features
                
                # Update status if ML confident
                if is_vuln_ml and ml_confidence > 0.85:
                    if result.status == ScanStatus.SAFE:
                        result.status = ScanStatus.SUSPICIOUS
                        result.confidence = ml_confidence
                        result.warnings.append(
                            f"ML detected suspicious patterns (confidence: {ml_confidence:.2f})"
                        )
                
            except Exception as e:
                logger.error(f"ML detection failed: {e}")
                result.warnings.append(f"ML detection error: {str(e)}")
        
        # Plugin execution
        if run_plugins and result.status != ScanStatus.VULNERABLE:
            try:
                plugin_results = self.plugin_manager.run_plugins(url, response)
                result.plugin_results = plugin_results
                
                # Check for plugin detections
                for plugin_name, plugin_result in plugin_results.items():
                    if plugin_result.get('vulnerable'):
                        result.status = ScanStatus.VULNERABLE
                        result.confidence = max(
                            result.confidence,
                            plugin_result.get('confidence', 0.7)
                        )
                        result.warnings.append(
                            f"Plugin '{plugin_name}' detected vulnerability: "
                            f"{plugin_result.get('details', 'No details')}"
                        )
                        
            except Exception as e:
                logger.error(f"Plugin execution failed: {e}")
                result.warnings.append(f"Plugin error: {str(e)}")
        
        # Calculate final risk score if not set
        if result.risk_score == 0.0 and result.status == ScanStatus.VULNERABLE:
            result.risk_score = result.confidence
        
        # Set summary
        if result.status == ScanStatus.VULNERABLE:
            result.summary = f"Vulnerable: {result.severity} risk detected via {result.status.value}"
        elif result.status == ScanStatus.SUSPICIOUS:
            result.summary = f"Suspicious patterns found (Confidence: {result.confidence:.2f})"
        elif result.status == ScanStatus.SAFE:
            result.summary = "No vulnerabilities detected"
        else:
            result.summary = result.errors[0] if result.errors else "Scan error occurred"

        # Finalize
        result.scan_duration = time.time() - scan_start
        
        # Cache result
        self._cache_result(url, result)
        
        # Store in history
        self.scan_history.append(result)
        if len(self.scan_history) > 1000:
            self.scan_history = self.scan_history[-1000:]
        
        # Update stats
        if result.status == ScanStatus.VULNERABLE:
            self.stats['scans_vulnerable'] += 1
        elif result.status == ScanStatus.SUSPICIOUS:
            self.stats['scans_suspicious'] += 1
        elif result.status == ScanStatus.SAFE:
            self.stats['scans_safe'] += 1
        
        # Broadcast to dashboard
        self._broadcast_result(result)
        
        return result

    def scan_url_with_ml(self, url: str) -> Dict:
        """
        Dashboard-compatible scanning method
        """
        result = self.scan_url(url, use_ml=True)
        return result.to_dashboard_dict()
    
    def scan_batch(
        self,
        urls: List[str],
        use_ml: bool = True,
        run_plugins: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> List[ScanResult]:
        """
        Scan multiple URLs in parallel
        
        Args:
            urls: List of URLs to scan
            use_ml: Use ML detection
            run_plugins: Run plugins
            progress_callback: Callback function(completed, total, result)
        
        Returns:
            List of ScanResult objects
        """
        results = []
        total = len(urls)
        
        logger.info(f"Starting batch scan of {total} URLs")
        
        # Submit all tasks
        futures = {
            self.executor.submit(
                self.scan_url, url, use_ml, run_plugins
            ): url for url in urls
        }
        
        # Collect results as they complete
        for i, future in enumerate(as_completed(futures), 1):
            url = futures[future]
            try:
                result = future.result()
                results.append(result)
                
                if progress_callback:
                    progress_callback(i, total, result)
                    
                logger.debug(f"Completed {i}/{total}: {url} -> {result.status.value}")
                
            except Exception as e:
                logger.error(f"Batch scan failed for {url}: {e}")
                # Create error result
                error_result = ScanResult(
                    url=url,
                    status=ScanStatus.ERROR
                )
                error_result.errors.append(str(e))
                results.append(error_result)
        
        logger.info(
            f"Batch scan completed: {len(results)} URLs processed, "
            f"{sum(1 for r in results if r.status == ScanStatus.VULNERABLE)} vulnerable"
        )
        
        return results
    
    async def scan_batch_async(
        self,
        urls: List[str],
        use_ml: bool = True,
        run_plugins: bool = True
    ) -> List[ScanResult]:
        """
        Async batch scanning for better performance
        
        Note: This is a simplified async version. For full async support,
        the entire detection pipeline would need to be async.
        """
        tasks = []
        for url in urls:
            task = self.fetch_url_async(url)
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        results = []
        for url, response_data in zip(urls, responses):
            if isinstance(response_data, Exception):
                result = ScanResult(url=url, status=ScanStatus.ERROR)
                result.errors.append(str(response_data))
                results.append(result)
                continue
            
            if response_data is None:
                result = ScanResult(url=url, status=ScanStatus.ERROR)
                result.errors.append("Failed to fetch")
                results.append(result)
                continue
            
            # For now, fall back to sync scanning for actual detection
            # Full async would require async detector
            result = self.scan_url(url, use_ml, run_plugins)
            results.append(result)
        
        return results
    
    def _broadcast_result(self, result: ScanResult):
        """Broadcast result to dashboard"""
        try:
            from dashboard import broadcast_update
            broadcast_update(result.to_dict())
        except ImportError:
            pass  # Dashboard not available
        except Exception as e:
            logger.debug(f"Failed to broadcast result: {e}")
    
    def get_statistics(self) -> Dict:
        """Get scanner statistics"""
        return {
            'total_scans': self.stats['scans_total'],
            'vulnerable': self.stats['scans_vulnerable'],
            'suspicious': self.stats['scans_suspicious'],
            'safe': self.stats['scans_safe'],
            'failed': self.stats['scans_failed'],
            'cached': self.stats['scans_cached'],
            'requests': {
                'success': self.stats['requests_success'],
                'timeout': self.stats['requests_timeout'],
                'connection_error': self.stats['requests_connection_error'],
                'proxy_error': self.stats['requests_proxy_error'],
                'error': self.stats['requests_error'],
            },
            'cache': {
                'hits': self.stats['cache_hits'],
                'misses': self.stats['cache_misses'],
                'size': len(self._cache),
            },
            'proxies': {
                'total': len(self.proxies),
                'healthy': len([p for p in self.proxies if p.health == ProxyHealth.HEALTHY]),
                'degraded': len([p for p in self.proxies if p.health == ProxyHealth.DEGRADED]),
                'failed': len([p for p in self.proxies if p.health == ProxyHealth.FAILED]),
            },
            'recent_scans': [
                {
                    'url': r.url,
                    'status': r.status.value,
                    'timestamp': r.timestamp,
                    'duration': r.scan_duration
                }
                for r in self.scan_history[-10:]
            ]
        }
    
    def get_proxy_health(self) -> List[Dict]:
        """Get health status of all proxies"""
        return [
            {
                'url': p.url,
                'health': p.health.value,
                'success_rate': p.success_rate,
                'avg_response_time': p.avg_response_time,
                'success_count': p.success_count,
                'failure_count': p.failure_count,
                'consecutive_failures': p.consecutive_failures,
            }
            for p in self.proxies
        ]
    
    def reset_statistics(self):
        """Reset all statistics"""
        self.stats.clear()
        self.scan_history.clear()
        self._cache.clear()
    
    def cleanup(self):
        """Cleanup resources"""
        self.executor.shutdown(wait=True)
        self.session.close()
        logger.info("URLScanner cleanup completed")


# Example usage
if __name__ == "__main__":
    # Configuration
    config = {
        'scanner': {
            'user_agent': 'VIPSQLi/3.0 (Advanced Scanner)',
            'timeout': 10,
            'max_retries': 3,
            'max_workers': 20,
            'cache_enabled': True,
            'proxy_rotation': False,
        },
        'rate_limit': {
            'requests_per_second': 5,
            'adaptive': True
        }
    }
    
    # Initialize scanner
    scanner = URLScanner(config)
    
    # Example: Single URL scan
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print("=== Single URL Scan ===")
    result = scanner.scan_url(test_url)
    
    print(f"\nURL: {result.url}")
    print(f"Status: {result.status.value}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Risk Score: {result.risk_score:.2f}")
    print(f"Severity: {result.severity}")
    print(f"Response Time: {result.response_time:.3f}s")
    print(f"Scan Duration: {result.scan_duration:.3f}s")
    
    if result.waf_detected:
        print(f"\n[WAF] Detected: {result.waf_name} (confidence: {result.waf_confidence:.2f})")
    
    if result.error_based:
        print(f"\n[Error-Based] Detected:")
        print(f"  Confidence: {result.error_based['confidence']:.2f}")
        print(f"  Indicators: {result.error_based['indicators'][:2]}")
    
    if result.errors:
        print(f"\n[Errors] {len(result.errors)} error(s):")
        for error in result.errors:
            print(f"  - {error}")
    
    if result.warnings:
        print(f"\n[Warnings] {len(result.warnings)} warning(s):")
        for warning in result.warnings:
            print(f"  - {warning}")
    
    # Example: Batch scan
    print("\n\n=== Batch URL Scan ===")
    test_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/artists.php?artist=2",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
    ]
    
    def progress_callback(completed, total, result):
        print(f"Progress: {completed}/{total} - {result.url} -> {result.status.value}")
    
    batch_results = scanner.scan_batch(test_urls, progress_callback=progress_callback)
    
    print(f"\nBatch scan completed:")
    print(f"  Total: {len(batch_results)}")
    print(f"  Vulnerable: {sum(1 for r in batch_results if r.status == ScanStatus.VULNERABLE)}")
    print(f"  Suspicious: {sum(1 for r in batch_results if r.status == ScanStatus.SUSPICIOUS)}")
    print(f"  Safe: {sum(1 for r in batch_results if r.status == ScanStatus.SAFE)}")
    
    # Statistics
    print("\n=== Scanner Statistics ===")
    stats = scanner.get_statistics()
    print(f"Total Scans: {stats['total_scans']}")
    print(f"Vulnerable: {stats['vulnerable']}")
    print(f"Cache Hit Rate: {stats['cache']['hits']/(stats['cache']['hits']+stats['cache']['misses'])*100:.1f}%")
    print(f"Success Rate: {stats['requests']['success']/(stats['total_scans'] or 1)*100:.1f}%")
    
    # Cleanup
    scanner.cleanup()
