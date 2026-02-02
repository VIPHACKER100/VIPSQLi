import numpy as np
import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter
import hashlib

class FeatureExtractor:
    """
    Enhanced feature extractor for SQL injection detection
    
    Improvements:
    - Advanced URL parsing features
    - SQL keyword detection and scoring
    - Entropy-based anomaly detection
    - Character distribution analysis
    - Payload complexity metrics
    - Enhanced response analysis
    """
    
    # SQL keywords and patterns for detection
    SQL_KEYWORDS = {
        'basic': ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter'],
        'functions': ['concat', 'substring', 'ascii', 'char', 'cast', 'convert'],
        'operators': ['and', 'or', 'xor', 'not', 'like', 'between'],
        'comments': ['--', '/*', '*/', '#'],
        'logic': ['true', 'false', 'null', 'is', 'exists'],
    }
    
    # SQL injection patterns
    SQLI_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(sleep\s*\()",
        r"(benchmark\s*\()",
        r"(waitfor\s+delay)",
        r"(\bexec\b.*\()",
        r"(load_file\s*\()",
        r"(into\s+outfile)",
        r"(information_schema)",
    ]
    
    def __init__(self):
        self.feature_names = [
            # URL-based features
            'url_length',
            'param_count',
            'has_numeric_param',
            'url_depth',
            'special_char_ratio',
            'url_entropy',
            
            # Parameter-based features
            'avg_param_length',
            'max_param_length',
            'param_entropy',
            'encoded_param_ratio',
            
            # SQL pattern features
            'sql_keyword_count',
            'sql_keyword_density',
            'union_select_detected',
            'comment_detected',
            'logical_operator_count',
            'sql_function_count',
            'injection_pattern_score',
            
            # Character analysis
            'quote_count',
            'dash_count',
            'semicolon_count',
            'parenthesis_balance',
            'special_sql_chars_ratio',
            
            # Response features
            'status_code',
            'response_time',
            'content_length',
            'error_in_response',
            
            # Detection features
            'waf_detected',
            'sql_error_detected',
            
            # Advanced features
            'payload_complexity',
            'obfuscation_score',
            'time_based_indicators',
        ]
        
        # Compile regex patterns
        self.sqli_pattern_regex = [re.compile(p, re.IGNORECASE) for p in self.SQLI_PATTERNS]
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * np.log2(count/length) for count in counter.values())
        return entropy
    
    def detect_encoding(self, text: str) -> float:
        """Detect URL encoding ratio"""
        if not text:
            return 0.0
        
        encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', text))
        return encoded_chars / max(len(text), 1)
    
    def count_sql_keywords(self, text: str) -> Dict[str, int]:
        """Count SQL keywords by category"""
        text_lower = text.lower()
        counts = {}
        
        for category, keywords in self.SQL_KEYWORDS.items():
            count = sum(len(re.findall(r'\b' + re.escape(kw) + r'\b', text_lower)) 
                       for kw in keywords)
            counts[category] = count
        
        return counts
    
    def calculate_injection_pattern_score(self, text: str) -> float:
        """Calculate score based on SQL injection patterns"""
        score = 0.0
        for pattern in self.sqli_pattern_regex:
            if pattern.search(text):
                score += 1.0
        
        # Normalize by number of patterns
        return min(score / len(self.sqli_pattern_regex), 1.0)
    
    def calculate_obfuscation_score(self, text: str) -> float:
        """Detect obfuscation techniques"""
        score = 0.0
        
        # Check for multiple encoding layers
        if '25' in text and '%' in text:  # Double encoding
            score += 0.3
        
        # Check for case variation (SeLeCt, etc.)
        words = re.findall(r'[a-zA-Z]+', text)
        mixed_case = sum(1 for w in words if w.lower() != w and w.upper() != w)
        if mixed_case > 0:
            score += min(mixed_case / max(len(words), 1), 0.3)
        
        # Check for concatenation operators
        concat_patterns = ['||', '/**/+', 'concat(', 'char(']
        score += min(sum(0.1 for p in concat_patterns if p in text.lower()), 0.4)
        
        return min(score, 1.0)
    
    def detect_time_based_indicators(self, text: str) -> float:
        """Detect time-based SQL injection indicators"""
        text_lower = text.lower()
        time_keywords = ['sleep', 'benchmark', 'waitfor', 'delay', 'pg_sleep']
        
        return 1.0 if any(kw in text_lower for kw in time_keywords) else 0.0
    
    def extract_url_features(self, url: str) -> Dict[str, float]:
        """Extract comprehensive URL-based features"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Decode URL for analysis
        decoded_url = unquote(url)
        
        # Basic URL metrics
        url_length = len(url)
        param_count = len(params)
        url_depth = len([p for p in parsed.path.split('/') if p])
        
        # Special characters
        special_chars = sum(1 for c in url if not c.isalnum() and c not in ['/', ':', '.', '?', '&', '='])
        special_char_ratio = special_chars / max(url_length, 1)
        
        # Entropy
        url_entropy = self.calculate_entropy(decoded_url)
        
        # Parameter analysis
        param_values = [v[0] for v in params.values() if v]
        avg_param_length = np.mean([len(p) for p in param_values]) if param_values else 0
        max_param_length = max([len(p) for p in param_values]) if param_values else 0
        param_entropy = np.mean([self.calculate_entropy(p) for p in param_values]) if param_values else 0
        encoded_param_ratio = self.detect_encoding(parsed.query)
        
        # Numeric parameter check
        has_numeric_param = 1.0 if any(v[0].isdigit() for v in params.values() if v) else 0.0
        
        # SQL pattern detection
        full_query = parsed.query + parsed.path
        sql_counts = self.count_sql_keywords(full_query)
        total_keywords = sum(sql_counts.values())
        keyword_density = total_keywords / max(len(full_query), 1)
        
        # Specific pattern detection
        union_select = 1.0 if re.search(r'\bunion\b.*\bselect\b', full_query.lower()) else 0.0
        comment_detected = 1.0 if any(c in full_query for c in ['--', '/*', '#']) else 0.0
        
        # Character counts
        quote_count = full_query.count("'") + full_query.count('"')
        dash_count = full_query.count('-')
        semicolon_count = full_query.count(';')
        
        # Parenthesis balance
        open_paren = full_query.count('(')
        close_paren = full_query.count(')')
        parenthesis_balance = abs(open_paren - close_paren) / max(open_paren + close_paren, 1)
        
        # SQL special characters
        sql_special = sum(1 for c in full_query if c in ["'", '"', ';', '--', '/*', '*/', '#'])
        special_sql_chars_ratio = sql_special / max(len(full_query), 1)
        
        # Pattern score
        injection_pattern_score = self.calculate_injection_pattern_score(full_query)
        
        # Complexity and obfuscation
        payload_complexity = (total_keywords + quote_count + parenthesis_balance * 10) / max(len(full_query), 1)
        obfuscation_score = self.calculate_obfuscation_score(full_query)
        time_based_indicators = self.detect_time_based_indicators(full_query)
        
        return {
            'url_length': url_length,
            'param_count': param_count,
            'has_numeric_param': has_numeric_param,
            'url_depth': url_depth,
            'special_char_ratio': special_char_ratio,
            'url_entropy': url_entropy,
            'avg_param_length': avg_param_length,
            'max_param_length': max_param_length,
            'param_entropy': param_entropy,
            'encoded_param_ratio': encoded_param_ratio,
            'sql_keyword_count': total_keywords,
            'sql_keyword_density': keyword_density,
            'union_select_detected': union_select,
            'comment_detected': comment_detected,
            'logical_operator_count': sql_counts.get('operators', 0),
            'sql_function_count': sql_counts.get('functions', 0),
            'injection_pattern_score': injection_pattern_score,
            'quote_count': quote_count,
            'dash_count': dash_count,
            'semicolon_count': semicolon_count,
            'parenthesis_balance': parenthesis_balance,
            'special_sql_chars_ratio': special_sql_chars_ratio,
            'payload_complexity': payload_complexity,
            'obfuscation_score': obfuscation_score,
            'time_based_indicators': time_based_indicators,
        }
    
    def extract_response_features(self, response) -> Dict[str, float]:
        """Extract enhanced response features"""
        if not response:
            return {
                'status_code': 0,
                'response_time': 0,
                'content_length': 0,
                'error_in_response': 0,
            }
        
        # Check for SQL errors in response
        error_keywords = [
            'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'odbc',
            'unclosed quotation', 'quoted string', 'syntax error',
            'warning: mysql', 'error in your sql syntax'
        ]
        
        response_text_lower = response.text.lower()
        error_detected = 1.0 if any(kw in response_text_lower for kw in error_keywords) else 0.0
        
        return {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
            'content_length': len(response.text),
            'error_in_response': error_detected,
        }
    
    def combine_features(self, url: str, response, detection_results: Dict[str, Any]) -> np.ndarray:
        """Combine all features into a feature vector"""
        url_feats = self.extract_url_features(url)
        resp_feats = self.extract_response_features(response)
        
        det_feats = {
            'waf_detected': 1.0 if detection_results.get('waf') else 0.0,
            'sql_error_detected': 1.0 if detection_results.get('errors') else 0.0,
        }
        
        all_features = {**url_feats, **resp_feats, **det_feats}
        
        # Ensure consistent order matching feature_names
        feature_vector = np.array([all_features.get(name, 0.0) for name in self.feature_names])
        
        return feature_vector
    
    def get_feature_importance_description(self) -> Dict[str, str]:
        """Return descriptions of features for interpretability"""
        return {
            'url_length': 'Total length of the URL',
            'param_count': 'Number of query parameters',
            'sql_keyword_count': 'Total SQL keywords detected',
            'injection_pattern_score': 'Score based on known SQLi patterns',
            'payload_complexity': 'Overall complexity of the payload',
            'obfuscation_score': 'Likelihood of obfuscation techniques',
            'response_time': 'Response time (useful for time-based SQLi)',
            'error_in_response': 'Presence of SQL errors in response',
        }