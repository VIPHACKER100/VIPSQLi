"""
Enhanced GraphQL Injection Detection Plugin

This plugin detects various GraphQL security vulnerabilities including:
- Introspection exposure
- SQL injection in GraphQL queries
- NoSQL injection in GraphQL queries
- Query depth/complexity abuse
- Batch query attacks
- Authorization bypass attempts
"""

import requests
import json
import logging
from typing import Tuple, Optional, Dict, Any, List
from plugins.base import PluginBase, PluginMetadata, PluginPriority

logger = logging.getLogger(__name__)


class GraphQLPlugin(PluginBase):
    """Advanced GraphQL security testing plugin."""
    
    # Configuration
    DEFAULT_TIMEOUT = 10
    MAX_RETRIES = 2
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="GraphQL Injection",
            version="2.0.0",
            author="VIPHacker100",
            description="Comprehensive GraphQL security vulnerability detection",
            priority=PluginPriority.NORMAL,
            tags=["graphql", "api", "injection"]
        )
    
    def supports_url(self, url: str) -> bool:
        """Check if URL is likely a GraphQL endpoint."""
        url_lower = url.lower()
        graphql_indicators = [
            '/graphql',
            '/api/graphql',
            '/v1/graphql',
            '/query',
            'query=',
            '/gql'
        ]
        return any(indicator in url_lower for indicator in graphql_indicators)
    
    def detect(self, url: str, response: Any = None) -> Tuple[bool, Optional[Dict]]:
        """
        Perform comprehensive GraphQL vulnerability detection.
        
        Args:
            url: Target GraphQL endpoint URL
            response: Optional initial response object
            
        Returns:
            Tuple of (vulnerability_found, details_dict)
        """
        vulnerabilities = {}
        
        # Test 1: Introspection exposure
        introspection_result = self._test_introspection(url)
        if introspection_result:
            vulnerabilities['introspection'] = introspection_result
        
        # Test 2: SQL Injection in GraphQL
        sqli_result = self._test_sql_injection(url)
        if sqli_result:
            vulnerabilities['sql_injection'] = sqli_result
        
        # Test 3: NoSQL Injection in GraphQL
        nosqli_result = self._test_nosql_injection(url)
        if nosqli_result:
            vulnerabilities['nosql_injection'] = nosqli_result
        
        # Test 4: Query depth/complexity abuse
        depth_result = self._test_query_depth(url)
        if depth_result:
            vulnerabilities['query_depth_abuse'] = depth_result
        
        # Test 5: Batch query attacks
        batch_result = self._test_batch_queries(url)
        if batch_result:
            vulnerabilities['batch_query_vulnerability'] = batch_result
        
        # Test 6: Field suggestion leakage
        field_result = self._test_field_suggestions(url)
        if field_result:
            vulnerabilities['field_suggestion_leakage'] = field_result
        
        # Test 7: Authorization bypass
        auth_result = self._test_authorization_bypass(url)
        if auth_result:
            vulnerabilities['authorization_bypass'] = auth_result
        
        if vulnerabilities:
            return True, {
                'vulnerabilities': vulnerabilities,
                'risk_level': self._calculate_risk_level(vulnerabilities),
                'recommendations': self._generate_recommendations(vulnerabilities)
            }
        
        return False, None
    
    def _make_request(self, url: str, payload: Dict[str, Any], 
                      headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Make a safe HTTP request with error handling.
        
        Args:
            url: Target URL
            payload: JSON payload to send
            headers: Optional custom headers
            
        Returns:
            Response object or None if request failed
        """
        default_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if headers:
            default_headers.update(headers)
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=default_headers,
                timeout=self.DEFAULT_TIMEOUT,
                verify=True,
                allow_redirects=False
            )
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout for {url}")
        except requests.exceptions.SSLError:
            logger.warning(f"SSL verification failed for {url}")
            # Optionally retry without verification for testing
            try:
                response = requests.post(
                    url,
                    json=payload,
                    headers=default_headers,
                    timeout=self.DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=False
                )
                return response
            except Exception as e:
                logger.error(f"Request failed even without SSL verification: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
        
        return None
    
    def _test_introspection(self, url: str) -> Optional[Dict]:
        """Test if GraphQL introspection is enabled."""
        queries = [
            # Full schema introspection
            {"query": "{ __schema { types { name } } }"},
            # Type introspection
            {"query": "{ __type(name: \"Query\") { name fields { name } } }"},
            # Inline fragments introspection
            {"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}
        ]
        
        for query in queries:
            response = self._make_request(url, query)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Check for introspection data in response
                    if '__schema' in str(data) or '__type' in str(data):
                        return {
                            'enabled': True,
                            'query': query['query'],
                            'severity': 'medium',
                            'description': 'GraphQL introspection is publicly accessible',
                            'exposed_data': self._extract_schema_info(data)
                        }
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def _test_sql_injection(self, url: str) -> Optional[Dict]:
        """Test for SQL injection vulnerabilities in GraphQL."""
        # SQL injection payloads
        sqli_payloads = [
            {"query": "{ user(id: \"1' OR '1'='1\") { name email } }"},
            {"query": "{ user(id: \"1; DROP TABLE users--\") { name } }"},
            {"query": "{ users(filter: \"'; SELECT * FROM users--\") { id name } }"},
            {"query": "query { product(id: \"1' UNION SELECT NULL, username, password FROM users--\") { name } }"},
            {"query": "{ search(term: \"test' AND 1=1--\") { results } }"}
        ]
        
        sql_error_indicators = [
            'sql syntax',
            'mysql',
            'postgresql',
            'sqlite',
            'ora-',
            'syntax error',
            'database error',
            'sql statement',
            'quoted string not properly terminated',
            'unclosed quotation mark'
        ]
        
        for payload in sqli_payloads:
            response = self._make_request(url, payload)
            if response:
                response_text = response.text.lower()
                
                # Check for SQL error messages
                if any(indicator in response_text for indicator in sql_error_indicators):
                    return {
                        'vulnerable': True,
                        'payload': payload['query'],
                        'severity': 'critical',
                        'description': 'SQL injection vulnerability detected via error messages',
                        'evidence': self._extract_error_snippet(response.text)
                    }
        
        return None
    
    def _test_nosql_injection(self, url: str) -> Optional[Dict]:
        """Test for NoSQL injection vulnerabilities in GraphQL."""
        # NoSQL injection payloads for MongoDB
        nosql_payloads = [
            {"query": "{ user(filter: {username: {$ne: null}}) { name email } }"},
            {"query": "{ users(where: {password: {$gt: \"\"}}) { id } }"},
            {"query": "{ login(username: {$regex: \".*\"}, password: {$regex: \".*\"}) { token } }"},
            {"query": "query { data(filter: {$where: \"this.password == 'test'\"}) { result } }"}
        ]
        
        for payload in nosql_payloads:
            response = self._make_request(url, payload)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Heuristic: successful response with operator injection might indicate vulnerability
                    if data and 'errors' not in str(data).lower() and len(str(data)) > 50:
                        return {
                            'vulnerable': True,
                            'payload': payload['query'],
                            'severity': 'high',
                            'description': 'Potential NoSQL injection - operators accepted without validation'
                        }
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def _test_query_depth(self, url: str) -> Optional[Dict]:
        """Test for query depth/complexity limitations."""
        # Create deeply nested query
        deep_query = self._generate_deep_query(depth=20)
        
        response = self._make_request(url, {"query": deep_query})
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'errors' not in str(data).lower():
                    return {
                        'vulnerable': True,
                        'severity': 'medium',
                        'description': 'No query depth limitation detected - potential DoS vector',
                        'max_depth_tested': 20
                    }
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _test_batch_queries(self, url: str) -> Optional[Dict]:
        """Test for batch query vulnerabilities."""
        # Batch query with multiple operations
        batch_payload = [
            {"query": "{ __typename }"},
            {"query": "{ __schema { types { name } } }"},
            {"query": "{ __type(name: \"Query\") { name } }"}
        ]
        
        response = self._make_request(url, batch_payload)
        if response and response.status_code == 200:
            try:
                data = response.json()
                # If all queries executed, batching is enabled
                if isinstance(data, list) and len(data) == len(batch_payload):
                    return {
                        'enabled': True,
                        'severity': 'low',
                        'description': 'Batch queries enabled - potential for amplification attacks'
                    }
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _test_field_suggestions(self, url: str) -> Optional[Dict]:
        """Test if field suggestions leak schema information."""
        # Query with typo to trigger suggestion
        payload = {"query": "{ usrr { name } }"}  # Typo: 'usrr' instead of 'user'
        
        response = self._make_request(url, payload)
        if response:
            try:
                data = response.json()
                error_msg = str(data).lower()
                # Look for field suggestions
                if 'did you mean' in error_msg or 'suggestion' in error_msg:
                    return {
                        'vulnerable': True,
                        'severity': 'low',
                        'description': 'Field suggestions enabled - schema enumeration possible',
                        'evidence': self._extract_error_snippet(str(data))
                    }
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _test_authorization_bypass(self, url: str) -> Optional[Dict]:
        """Test for authorization bypass vulnerabilities."""
        # Try accessing admin/sensitive fields without auth
        auth_payloads = [
            {"query": "{ admin { users { id email password } } }"},
            {"query": "{ allUsers { id email role isAdmin } }"},
            {"query": "{ sensitive { apiKey secretToken } }"}
        ]
        
        for payload in auth_payloads:
            response = self._make_request(url, payload)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # If we get data instead of auth error, might be vulnerable
                    if data and 'data' in str(data) and 'unauthorized' not in str(data).lower():
                        return {
                            'vulnerable': True,
                            'severity': 'critical',
                            'description': 'Potential authorization bypass - sensitive fields accessible',
                            'payload': payload['query']
                        }
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def _generate_deep_query(self, depth: int) -> str:
        """Generate a deeply nested GraphQL query."""
        query = "{ __typename "
        for i in range(depth):
            query += "{ __typename "
        for i in range(depth):
            query += "}"
        query += "}"
        return query
    
    def _extract_schema_info(self, data: Dict) -> Dict:
        """Extract useful schema information from introspection data."""
        schema_info = {}
        try:
            if '__schema' in str(data):
                schema_info['schema_accessible'] = True
            if 'types' in str(data):
                schema_info['types_exposed'] = True
            if 'fields' in str(data):
                schema_info['fields_exposed'] = True
        except Exception:
            pass
        return schema_info
    
    def _extract_error_snippet(self, text: str, max_length: int = 200) -> str:
        """Extract relevant error snippet from response."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."
    
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
        
        if 'introspection' in vulnerabilities:
            recommendations.append("Disable GraphQL introspection in production environments")
        
        if 'sql_injection' in vulnerabilities:
            recommendations.append("Implement parameterized queries and input validation")
            recommendations.append("Use an ORM with built-in SQL injection protection")
        
        if 'nosql_injection' in vulnerabilities:
            recommendations.append("Validate and sanitize all user inputs")
            recommendations.append("Avoid using MongoDB operators in user-controlled fields")
        
        if 'query_depth_abuse' in vulnerabilities:
            recommendations.append("Implement query depth and complexity limits")
            recommendations.append("Use query cost analysis to prevent DoS attacks")
        
        if 'batch_query_vulnerability' in vulnerabilities:
            recommendations.append("Implement rate limiting for batch queries")
            recommendations.append("Set maximum batch size limits")
        
        if 'authorization_bypass' in vulnerabilities:
            recommendations.append("Implement proper field-level authorization")
            recommendations.append("Use middleware to enforce access control")
        
        if 'field_suggestion_leakage' in vulnerabilities:
            recommendations.append("Disable field suggestions in production")
        
        return recommendations