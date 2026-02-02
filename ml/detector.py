import numpy as np
import joblib
from pathlib import Path
from typing import Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from utils.logger import get_logger

logger = get_logger("vipsqli.ml")

class MLDetector:
    def __init__(self, model_path: str = None, threshold: float = 0.7):
        self.threshold = threshold
        self.model = None
        self.scaler = None
        self.is_trained = False
        
        # Default model path
        if not model_path:
            model_path = Path(__file__).parent / "models" / "default.pkl"
            
        self.model_path = Path(model_path)
        
        if self.model_path.exists():
            self.load_model(str(self.model_path))
        else:
            logger.warning(f"ML model not found at {self.model_path}")

    def train(self, X: np.ndarray, y: np.ndarray):
        """Train a new Random Forest model"""
        logger.info("Training ML model...")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_scaled, y)
        self.is_trained = True
        logger.info("Training complete")

    def predict(self, features: np.ndarray) -> Tuple[bool, float]:
        """Predict if features indicate vulnerability"""
        if not self.is_trained:
            return False, 0.0
        
        try:
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            features_scaled = self.scaler.transform(features)
            proba = self.model.predict_proba(features_scaled)[0]
            vuln_prob = proba[1]  # Probability of class 1 (vulnerable)
            
            return vuln_prob >= self.threshold, vuln_prob
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return False, 0.0

    def save_model(self, path: str = None):
        """Save trained model to disk"""
        save_path = path or str(self.model_path)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump({
            'model': self.model, 
            'scaler': self.scaler
        }, save_path)
        logger.info(f"Model saved to {save_path}")

    def load_model(self, path: str):
        """Load model from disk"""
        try:
            data = joblib.load(path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
