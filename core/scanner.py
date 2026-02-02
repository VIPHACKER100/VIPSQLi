from typing import Dict, Optional
import requests
import random
from urllib.parse import urlparse, parse_qs
from utils.logger import get_logger
from utils.rate_limiter import AdaptiveRateLimiter
from plugins.manager import PluginManager

logger = get_logger("vipsqli.core")

class URLScanner:
    def __init__(self, config: Dict, plugin_manager=None):
        self.config = config
        self.session = requests.Session()
        self.user_agent = config.get('scanner', {}).get('user_agent', 'VIPSQLi/2.2')
        self.timeout = config.get('scanner', {}).get('timeout', 10)
        self.proxies = [] 
        
        self.rate_limiter = AdaptiveRateLimiter(config)
        self.plugin_manager = plugin_manager or PluginManager(config)
        self.plugin_manager.load_all_plugins()
        
        # Setup session defaults
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'keep-alive'
        })

    def set_proxies(self, proxies: list):
        self.proxies = proxies

    def _get_random_proxy(self) -> Optional[Dict]:
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def fetch_url(self, url: str) -> Optional[requests.Response]:
        """Fetch a URL with configured settings"""
        self.rate_limiter.acquire()
        try:
            proxy = self._get_random_proxy()
            response = self.session.get(
                url, 
                timeout=self.timeout,
                proxies=proxy,
                allow_redirects=True
            )
            
            # Report status to rate limiter
            if response.status_code in [429, 503]:
                self.rate_limiter.report_error(response.status_code)
            else:
                self.rate_limiter.report_success()
                
            return response
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None

    def is_static_file(self, url: str) -> bool:
        """Check if URL points to a static resource"""
        static_exts = (
            '.css', '.js', '.png', '.jpg', '.gif', '.pdf', '.svg', '.woff',
            '.ttf', '.ico', '.mp4', '.zip'
        )
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in static_exts)

    def extract_parameters(self, url: str) -> Dict:
        """Extract query parameters from URL"""
        return parse_qs(urlparse(url).query)

    def scan_url_with_ml(self, url: str, ml_detector=None) -> Dict:
        """Scan URL using hybrid detection (Pattern + ML)"""
        from core.detector import SQLiDetector
        # Import inside method to avoid circular imports if not needed globally yet
        try:
            from ml.features import FeatureExtractor
        except ImportError:
            FeatureExtractor = None

        detector = SQLiDetector(self.config)
        response = self.fetch_url(url)
        
        result = {
            'url': url,
            'verdict': 'SAFE',
            'details': None,
            'ml_confidence': 0.0,
            'waf_detected': False
        }

        if not response:
            result['verdict'] = 'ERROR'
            return result
        
        # Traditional detection
        has_error, errors = detector.detect_error_based(response.text)
        waf_detected, waf_name = detector.detect_waf(response.headers, response.text)
        
        result['waf_detected'] = waf_detected
        if waf_detected:
            result['waf_name'] = waf_name

        # ML prediction
        if ml_detector and FeatureExtractor:
            extractor = FeatureExtractor()
            features = extractor.combine_features(
                url, response, {'errors': errors, 'waf': waf_detected}
            )
            is_vuln_ml, confidence = ml_detector.predict(features)
            result['ml_confidence'] = float(confidence)
            
            if has_error:
                result['verdict'] = 'VULNERABLE'
                result['details'] = errors
            elif is_vuln_ml and confidence > 0.85:
                result['verdict'] = 'SUSPICIOUS'
                result['details'] = ['ML Detected Pattern']
        else:
            if has_error:
                result['verdict'] = 'VULNERABLE'
                result['details'] = errors
        
        # Run Plugins
        if result['verdict'] != 'VULNERABLE':
            plugin_results = self.plugin_manager.run_plugins(url, response)
            result['plugins'] = plugin_results
            for name, p_res in plugin_results.items():
                if p_res.get('vulnerable'):
                    result['verdict'] = 'VULNERABLE'
                    # Append details if exists
                    if not result['details']:
                         result['details'] = []
                    result['details'].append(f"Plugin: {name} - {p_res.get('details')}")
        
        # Dashboard Broadcast
        try:
            from dashboard import broadcast_update
            broadcast_update(result)
        except Exception:
            pass # Dashboard might not be enabled or import failed
            
        return result
