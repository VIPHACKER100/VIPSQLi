import time
import threading
from typing import Dict

class AdaptiveRateLimiter:
    def __init__(self, config: Dict):
        rate_config = config.get('rate_limiting', {})
        self.rps = rate_config.get('requests_per_second', 5)
        self.adaptive = rate_config.get('adaptive', True)
        
        # Initial delay calculation
        self.current_delay = 1.0 / self.rps if self.rps > 0 else 0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Block until allowed to proceed"""
        if self.current_delay > 0:
            with self.lock:
                time.sleep(self.current_delay)
    
    def report_error(self, status_code: int):
        """Increase delay on error (429/503)"""
        if self.adaptive and status_code in [429, 503]:
            with self.lock:
                self.current_delay = min(self.current_delay * 2, 5.0) # Max 5s delay
    
    def report_success(self):
        """Decrease delay on success"""
        if self.adaptive and self.current_delay > (1.0 / self.rps):
            with self.lock:
                self.current_delay = max(self.current_delay / 1.5, 1.0 / self.rps)
