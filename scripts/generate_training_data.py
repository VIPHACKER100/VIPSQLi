"""
Enhanced Training Data Generator for SQLi Detection ML Model
Generates realistic synthetic samples with improved feature engineering
"""
import sys
import os
import random
import numpy as np
from typing import List, Tuple

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import get_session, init_db
from database.models import MLTrainingData


class EnhancedDataGenerator:
    """Generate realistic synthetic SQLi training data"""
    
    # Common SQL injection patterns
    SQLI_PATTERNS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "' OR 'x'='x",
        "1' ORDER BY 1--",
        "' HAVING 1=1--",
        "' GROUP BY columnname HAVING 1=1--",
        "UNION ALL SELECT NULL,NULL,NULL--",
        "' AND 1=0 UNION ALL SELECT",
        "' WAITFOR DELAY '00:00:05'--",
        "'; EXEC sp_",
        "1' AND SLEEP(5)--",
        "' OR BENCHMARK(10000000,MD5(1))--"
    ]
    
    # Safe URL patterns
    SAFE_PATTERNS = [
        "id=123",
        "page=home",
        "category=electronics",
        "search=laptop",
        "user=john_doe",
        "filter=price_asc",
        "sort=date",
        "view=grid",
        "lang=en",
        "theme=dark"
    ]
    
    def __init__(self):
        self.rng = np.random.default_rng(42)  # Reproducible randomness
    
    def generate_safe_features(self) -> List[float]:
        """Generate features for safe/benign requests"""
        return [
            self.rng.uniform(10, 60),           # url_length (shorter)
            self.rng.integers(0, 4),            # param_count (fewer params)
            self.rng.integers(0, 2),            # has_numeric_param
            200,                                 # status_code (normal)
            self.rng.uniform(0.05, 0.3),        # response_time (faster)
            self.rng.uniform(800, 5000),        # content_length
            0,                                   # waf_detected (no WAF trigger)
            0                                    # sql_error_detected (no errors)
        ]
    
    def generate_vulnerable_features(self, attack_type: str = "basic") -> List[float]:
        """Generate features for vulnerable/attack requests"""
        if attack_type == "time_based":
            # Time-based blind SQLi
            response_time = self.rng.uniform(3.0, 10.0)  # Delayed response
            sql_error = 0  # No visible error
        elif attack_type == "union_based":
            # Union-based SQLi
            response_time = self.rng.uniform(0.2, 1.0)
            sql_error = self.rng.choice([0, 1])  # May or may not error
        elif attack_type == "error_based":
            # Error-based SQLi
            response_time = self.rng.uniform(0.1, 0.5)
            sql_error = 1  # Always errors
        else:  # basic
            response_time = self.rng.uniform(0.1, 2.0)
            sql_error = self.rng.choice([0, 1])
        
        return [
            self.rng.uniform(40, 150),          # url_length (longer, complex)
            self.rng.integers(1, 8),            # param_count (more params)
            self.rng.integers(0, 2),            # has_numeric_param
            self.rng.choice([200, 500]),        # status_code (may error)
            response_time,                       # response_time (varies by type)
            self.rng.uniform(100, 8000),        # content_length
            self.rng.choice([0, 1]),            # waf_detected (50/50)
            sql_error                            # sql_error_detected
        ]
    
    def generate_edge_case_features(self, case_type: str) -> List[float]:
        """Generate edge case samples for better model robustness"""
        if case_type == "false_positive":
            # Legitimate long queries that might look suspicious
            return [
                self.rng.uniform(80, 120),      # url_length (long but safe)
                self.rng.integers(5, 10),       # param_count (many params)
                1,                               # has_numeric_param
                200,                             # status_code
                self.rng.uniform(0.3, 0.8),     # response_time
                self.rng.uniform(2000, 6000),   # content_length
                0,                               # waf_detected
                0                                # sql_error_detected
            ]
        elif case_type == "evasion_attempt":
            # Obfuscated or encoded SQLi attempts
            return [
                self.rng.uniform(60, 100),      # url_length (medium)
                self.rng.integers(3, 7),        # param_count
                self.rng.integers(0, 2),        # has_numeric_param
                200,                             # status_code (might succeed)
                self.rng.uniform(0.5, 2.0),     # response_time
                self.rng.uniform(500, 4000),    # content_length
                1,                               # waf_detected (WAF triggered)
                0                                # sql_error_detected (evasion)
            ]
        else:  # noisy_data
            # Unusual but legitimate traffic
            return [
                self.rng.uniform(15, 90),       # url_length
                self.rng.integers(1, 6),        # param_count
                self.rng.integers(0, 2),        # has_numeric_param
                self.rng.choice([200, 404]),    # status_code
                self.rng.uniform(0.1, 1.5),     # response_time
                self.rng.uniform(300, 7000),    # content_length
                0,                               # waf_detected
                0                                # sql_error_detected
            ]
    
    def generate_url(self, pattern_type: str, index: int) -> str:
        """Generate realistic URL based on pattern type"""
        if pattern_type == "safe":
            param = random.choice(self.SAFE_PATTERNS)
            return f"/api/data?{param}&ref={index}"
        elif pattern_type == "vulnerable":
            base_param = random.choice(["id", "user", "search", "filter"])
            injection = random.choice(self.SQLI_PATTERNS)
            return f"/api/query?{base_param}={injection}"
        else:  # edge_case
            return f"/complex/endpoint?param1=value&param2={index}&filter=complex"


def generate_enhanced_samples(
    safe_count: int = 1000,
    vuln_count: int = 400,
    edge_case_count: int = 200
):
    """
    Generate enhanced synthetic training samples
    
    Args:
        safe_count: Number of safe samples to generate
        vuln_count: Number of vulnerable samples to generate
        edge_case_count: Number of edge case samples to generate
    """
    print("=" * 60)
    print("Enhanced Training Data Generator v2.0")
    print("=" * 60)
    
    print("\n[1/4] Initializing database...")
    init_db()
    session = get_session()
    
    generator = EnhancedDataGenerator()
    total_samples = safe_count + vuln_count + edge_case_count
    
    print(f"\n[2/4] Generating {safe_count} safe samples...")
    for i in range(safe_count):
        features = generator.generate_safe_features()
        url = generator.generate_url("safe", i)
        session.add(MLTrainingData(
            url=url,
            features=features,
            label=0,  # Safe
            verified=True
        ))
        if (i + 1) % 200 == 0:
            print(f"  Progress: {i + 1}/{safe_count} safe samples")
    
    print(f"\n[3/4] Generating {vuln_count} vulnerable samples...")
    attack_types = ["basic", "union_based", "error_based", "time_based"]
    for i in range(vuln_count):
        attack_type = random.choice(attack_types)
        features = generator.generate_vulnerable_features(attack_type)
        url = generator.generate_url("vulnerable", i)
        session.add(MLTrainingData(
            url=url,
            features=features,
            label=1,  # Vulnerable
            verified=True
        ))
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{vuln_count} vulnerable samples ({attack_type})")
    
    print(f"\n[4/4] Generating {edge_case_count} edge case samples...")
    edge_types = ["false_positive", "evasion_attempt", "noisy_data"]
    for i in range(edge_case_count):
        edge_type = random.choice(edge_types)
        features = generator.generate_edge_case_features(edge_type)
        url = generator.generate_url("edge_case", i)
        # Edge cases are split between safe (60%) and vulnerable (40%)
        label = 0 if random.random() < 0.6 else 1
        session.add(MLTrainingData(
            url=url,
            features=features,
            label=label,
            verified=True
        ))
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{edge_case_count} edge cases ({edge_type})")
    
    try:
        print("\n[5/5] Committing to database...")
        session.commit()
        print("\n" + "=" * 60)
        print("SUCCESS!")
        print("=" * 60)
        print(f"Total samples generated: {total_samples}")
        print(f"  - Safe samples: {safe_count}")
        print(f"  - Vulnerable samples: {vuln_count}")
        print(f"  - Edge case samples: {edge_case_count}")
        print(f"\nClass distribution:")
        safe_total = safe_count + int(edge_case_count * 0.6)
        vuln_total = vuln_count + int(edge_case_count * 0.4)
        print(f"  - Label 0 (Safe): {safe_total} ({safe_total/total_samples*100:.1f}%)")
        print(f"  - Label 1 (Vulnerable): {vuln_total} ({vuln_total/total_samples*100:.1f}%)")
        print("=" * 60)
        return True
    except Exception as e:
        session.rollback()
        print(f"\n[ERROR] Failed to generate data: {e}")
        return False
    finally:
        session.close()


if __name__ == "__main__":
    # Default: 1000 safe, 400 vulnerable, 200 edge cases (1600 total)
    # Adjust these numbers based on your needs
    success = generate_enhanced_samples(
        safe_count=1000,
        vuln_count=400,
        edge_case_count=200
    )
    
    sys.exit(0 if success else 1)