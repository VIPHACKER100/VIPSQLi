import requests
import json
from typing import Tuple, Optional, Dict, Any
from plugins.base import PluginBase

class GraphQLPlugin(PluginBase):
    @property
    def name(self) -> str:
        return "GraphQL Injection"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def supports_url(self, url: str) -> bool:
        return '/graphql' in url.lower() or 'query=' in url.lower()
    
    def detect(self, url: str, response: Any) -> Tuple[bool, Optional[Dict]]:
        # Test introspection
        query = {"query": "{ __schema { types { name } } }"}
        try:
            # We use a new request here because we need to send specific payload
            # In a real integration, we might use the shared session from scanner
            r = requests.post(url, json=query, timeout=10)
            if '__schema' in r.text and 'types' in r.text:
                return True, {'introspection_enabled': True}
        except:
            pass
        
        # Test SQLi in GraphQL
        sqli_query = {"query": "{ user(id: \"1' OR '1'='1\") { name } }"}
        try:
            r = requests.post(url, json=sqli_query, timeout=10)
            if 'sql' in r.text.lower() and 'error' in r.text.lower():
                return True, {'sql_injection': True}
        except:
            pass
        
        return False, None
