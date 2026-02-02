# Generate synthetic safe/vulnerable samples
import sys
import os
import random
import numpy as np

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import get_session, init_db
from database.models import MLTrainingData

def generate_samples():
    print("Initializing database...")
    init_db()
    session = get_session()
    
    print("Generating synthetic samples...")
    # Safe samples (500)
    for i in range(500):
        # Synthetic feature generation
        # Feature order: url_len, params, numeric, status, time, len, waf, sql_error
        features = [
            random.uniform(10, 50),   # url_length
            random.randint(0, 5),     # param_count
            random.randint(0, 1),     # has_numeric_param
            200,                      # status_code
            random.uniform(0.1, 0.5), # response_time
            random.uniform(500, 5000),# content_length
            0,                        # waf_detected
            0                         # sql_error_detected
        ]
        session.add(MLTrainingData(
            url=f"synthetic_safe_{i}",
            features=features,
            label=0,
            verified=True
        ))
    
    # Vulnerable samples (200)
    for i in range(200):
        features = [
            random.uniform(20, 100),  # url_length
            random.randint(1, 10),    # param_count
            random.randint(0, 1),     # has_numeric_param
            200,                      # status_code
            random.uniform(0.1, 1.0), # response_time
            random.uniform(500, 5000),# content_length
            random.choice([0, 1]),    # waf_detected
            1                         # sql_error_detected (Critical feature)
        ]
        session.add(MLTrainingData(
            url=f"synthetic_vuln_{i}",
            features=features,
            label=1,
            verified=True
        ))
    
    try:
        session.commit()
        print("Generated 700 training samples")
    except Exception as e:
        session.rollback()
        print(f"Error generating data: {e}")

if __name__ == "__main__":
    generate_samples()
