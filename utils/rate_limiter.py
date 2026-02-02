import time
import threading
from typing import Dict, Optional
from collections import deque
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket algorithm for rate limiting"""
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now


class AdaptiveRateLimiter:
    """Enhanced rate limiter with token bucket and adaptive behavior"""
    
    def __init__(self, config: Dict):
        rate_config = config.get('rate_limiting', {})
        self.rps = rate_config.get('requests_per_second', 5)
        self.burst_size = rate_config.get('burst_size', self.rps * 2)
        self.adaptive = rate_config.get('adaptive', True)
        self.max_backoff = rate_config.get('max_backoff', 60.0)
        self.min_delay = 1.0 / self.rps if self.rps > 0 else 0
        
        # Token bucket for burst handling
        self.bucket = TokenBucket(capacity=self.burst_size, refill_rate=self.rps)
        
        # Adaptive delay mechanism
        self.current_delay = self.min_delay
        self.lock = threading.Lock()
        
        # Statistics tracking
        self.stats = {
            'requests': 0,
            'throttled': 0,
            'errors': 0,
            'success': 0,
            'avg_delay': self.min_delay
        }
        
        # Sliding window for error rate tracking
        self.error_window = deque(maxlen=100)
        self.window_lock = threading.Lock()
        
        logger.info(f"Rate limiter initialized: {self.rps} RPS, burst: {self.burst_size}")
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Block until allowed to proceed or timeout.
        Returns True if acquired, False if timeout.
        """
        start_time = time.time()
        
        while True:
            # Try to consume token from bucket
            if self.bucket.consume():
                # Apply adaptive delay
                if self.current_delay > 0:
                    time.sleep(self.current_delay)
                
                with self.lock:
                    self.stats['requests'] += 1
                return True
            
            # Check timeout
            if timeout and (time.time() - start_time) >= timeout:
                with self.lock:
                    self.stats['throttled'] += 1
                return False
            
            # Wait before retry
            time.sleep(0.01)
    
    def report_error(self, status_code: int, response_time: Optional[float] = None):
        """Report an error and adjust rate if needed"""
        with self.lock:
            self.stats['errors'] += 1
        
        with self.window_lock:
            self.error_window.append((time.time(), status_code))
        
        # Adaptive backoff for rate limiting errors
        if self.adaptive:
            if status_code in [429, 503]:
                self._increase_delay()
                logger.warning(f"Rate limit hit (HTTP {status_code}), increasing delay to {self.current_delay:.3f}s")
            elif status_code >= 500:
                # Server errors might indicate overload
                self._increase_delay(factor=1.2)
    
    def report_success(self, response_time: Optional[float] = None):
        """Report success and potentially decrease delay"""
        with self.lock:
            self.stats['success'] += 1
        
        if self.adaptive and self._get_error_rate() < 0.05:  # Less than 5% error rate
            self._decrease_delay()
    
    def _increase_delay(self, factor: float = 2.0):
        """Increase delay with exponential backoff"""
        with self.lock:
            self.current_delay = min(self.current_delay * factor, self.max_backoff)
            self._update_avg_delay()
    
    def _decrease_delay(self):
        """Decrease delay gradually"""
        with self.lock:
            if self.current_delay > self.min_delay:
                self.current_delay = max(self.current_delay / 1.5, self.min_delay)
                self._update_avg_delay()
    
    def _update_avg_delay(self):
        """Update average delay stat"""
        if self.stats['requests'] > 0:
            alpha = 0.1  # Smoothing factor
            self.stats['avg_delay'] = (alpha * self.current_delay + 
                                      (1 - alpha) * self.stats['avg_delay'])
    
    def _get_error_rate(self) -> float:
        """Calculate recent error rate from sliding window"""
        with self.window_lock:
            if not self.error_window:
                return 0.0
            
            # Count errors in last 60 seconds
            now = time.time()
            recent_errors = sum(1 for ts, _ in self.error_window if now - ts < 60)
            
            # Compare to total requests in same period
            total_recent = max(1, len(self.error_window))
            return recent_errors / total_recent
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self.lock:
            stats = self.stats.copy()
        
        stats['current_delay'] = self.current_delay
        stats['error_rate'] = self._get_error_rate()
        stats['available_tokens'] = self.bucket.tokens
        
        return stats
    
    def reset(self):
        """Reset the rate limiter to initial state"""
        with self.lock:
            self.current_delay = self.min_delay
            self.bucket.tokens = self.bucket.capacity
            self.stats = {
                'requests': 0,
                'throttled': 0,
                'errors': 0,
                'success': 0,
                'avg_delay': self.min_delay
            }
        
        with self.window_lock:
            self.error_window.clear()
        
        logger.info("Rate limiter reset")


class DistributedRateLimiter:
    """Rate limiter that can coordinate across multiple instances (placeholder for Redis integration)"""
    
    def __init__(self, config: Dict, redis_client=None):
        self.local_limiter = AdaptiveRateLimiter(config)
        self.redis_client = redis_client
        self.key_prefix = config.get('rate_limiting', {}).get('redis_key_prefix', 'sqli_scanner')
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire using local limiter (Redis integration would go here)"""
        # For now, just use local limiter
        # In production, this would check Redis for distributed rate limiting
        return self.local_limiter.acquire(timeout)
    
    def report_error(self, status_code: int, response_time: Optional[float] = None):
        self.local_limiter.report_error(status_code, response_time)
    
    def report_success(self, response_time: Optional[float] = None):
        self.local_limiter.report_success(response_time)
    
    def get_stats(self) -> Dict:
        return self.local_limiter.get_stats()