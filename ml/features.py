import numpy as np
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'url_length',
            'param_count',
            'has_numeric_param',
            'status_code',
            'response_time',
            'content_length',
            'waf_detected',
            'sql_error_detected',
        ]
    
    def extract_url_features(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        return {
            'url_length': len(url),
            'param_count': len(params),
            'has_numeric_param': 1.0 if any(v[0].isdigit() for v in params.values() if v) else 0.0,
        }
    
    def extract_response_features(self, response) -> Dict[str, float]:
        if not response:
            return {
                'status_code': 0,
                'response_time': 0,
                'content_length': 0
            }
            
        return {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'content_length': len(response.text),
        }
    
    def combine_features(self, url: str, response, detection_results: Dict[str, Any]) -> np.ndarray:
        url_feats = self.extract_url_features(url)
        resp_feats = self.extract_response_features(response)
        
        det_feats = {
            'waf_detected': 1.0 if detection_results.get('waf') else 0.0,
            'sql_error_detected': 1.0 if detection_results.get('errors') else 0.0,
        }
        
        all_features = {**url_feats, **resp_feats, **det_feats}
        
        # Ensure consistent order matching feature_names
        return np.array([all_features.get(name, 0.0) for name in self.feature_names])
