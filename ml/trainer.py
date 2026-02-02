from database import get_session
from database.models import MLTrainingData
from ml.detector import MLDetector
import numpy as np
import logging

logger = logging.getLogger("vipsqli.trainer")

def train_model(min_samples: int = 100):
    session = get_session()
    # In a real scenario, filter for verified data: .filter_by(verified=True)
    # For initial testing, we might use all data if verification isn't fully implemented
    data = session.query(MLTrainingData).all()
    
    if len(data) < min_samples:
        print(f"Need {min_samples} samples, have {len(data)}")
        return False
    
    print(f"Training with {len(data)} samples...")
    X = np.array([d.features for d in data])
    y = np.array([d.label for d in data])
    
    detector = MLDetector()
    detector.train(X, y)
    detector.save_model()
    
    print(f"Trained model with {len(data)} samples and saved to disk.")
    return True
