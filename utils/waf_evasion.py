import random
import urllib.parse
from typing import Dict

class WAFEvasion:
    def __init__(self, config: Dict):
        self.enabled = config.get('waf_evasion', {}).get('enabled', False)
    
    def apply_evasion(self, payload: str, technique: str = 'random') -> str:
        if not self.enabled:
            return payload
        
        techniques = ['random_case', 'comment_injection', 'encoding']
        if technique == 'random' or technique not in techniques:
            technique = random.choice(techniques)
        
        if technique == 'random_case':
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        elif technique == 'comment_injection':
            # Simple example: replace space with comments
            return payload.replace(' ', '/**/')
        elif technique == 'encoding':
            return urllib.parse.quote(payload)
        
        return payload
