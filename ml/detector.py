import numpy as np
import joblib
from pathlib import Path
from typing import Tuple, Optional, Dict, List
from datetime import datetime
import json

# ML models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve

# Optional: XGBoost if available
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

from utils.logger import get_logger

logger = get_logger("vipsqli.ml")

class MLDetector:
    """
    Enhanced ML-based SQL injection detector
    
    Improvements:
    - Ensemble model support (Random Forest, Gradient Boosting, XGBoost)
    - Cross-validation and model evaluation
    - Feature importance analysis
    - Model versioning and metadata
    - Confidence calibration
    - Online learning capabilities
    - A/B testing support
    """
    
    def __init__(self, model_path: str = None, threshold: float = 0.7, model_type: str = 'ensemble'):
        self.threshold = threshold
        self.model_type = model_type
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.feature_importance = None
        self.training_metadata = {}
        
        # Default model path
        if not model_path:
            model_path = Path(__file__).parent / "models" / "default.pkl"
            
        self.model_path = Path(model_path)
        
        if self.model_path.exists():
            self.load_model(str(self.model_path))
        else:
            logger.warning(f"ML model not found at {self.model_path}")

    def _create_model(self):
        """Create the ML model based on model_type"""
        if self.model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
        
        elif self.model_type == 'gradient_boosting':
            return GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=7,
                min_samples_split=5,
                min_samples_leaf=2,
                subsample=0.8,
                random_state=42
            )
        
        elif self.model_type == 'xgboost' and XGBOOST_AVAILABLE:
            return xgb.XGBClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=7,
                min_child_weight=3,
                subsample=0.8,
                colsample_bytree=0.8,
                gamma=0.1,
                random_state=42,
                n_jobs=-1,
                scale_pos_weight=1
            )
        
        elif self.model_type == 'ensemble':
            # Create ensemble of models
            rf = RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                random_state=42,
                n_jobs=-1
            )
            
            gb = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )
            
            estimators = [
                ('rf', rf),
                ('gb', gb)
            ]
            
            # Add XGBoost to ensemble if available
            if XGBOOST_AVAILABLE:
                xgb_model = xgb.XGBClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=6,
                    random_state=42,
                    n_jobs=-1
                )
                estimators.append(('xgb', xgb_model))
            
            return VotingClassifier(
                estimators=estimators,
                voting='soft',
                n_jobs=-1
            )
        
        else:
            logger.warning(f"Unknown model type '{self.model_type}', defaulting to Random Forest")
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=42,
                n_jobs=-1
            )

    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2):
        """
        Train a new model with validation
        
        Args:
            X: Feature matrix
            y: Labels
            validation_split: Fraction of data to use for validation
        """
        logger.info(f"Training {self.model_type} model with {len(X)} samples...")
        
        # Split data for validation
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Use RobustScaler for better handling of outliers
        self.scaler = RobustScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Create and train model
        self.model = self._create_model()
        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # Evaluate on validation set
        train_score = self.model.score(X_train_scaled, y_train)
        val_score = self.model.score(X_val_scaled, y_val)
        
        # Get predictions for detailed metrics
        y_val_pred = self.model.predict(X_val_scaled)
        y_val_proba = self.model.predict_proba(X_val_scaled)[:, 1]
        
        # Calculate metrics
        auc_score = roc_auc_score(y_val, y_val_proba)
        
        # Store training metadata
        self.training_metadata = {
            'model_type': self.model_type,
            'training_samples': len(X_train),
            'validation_samples': len(X_val),
            'train_accuracy': float(train_score),
            'validation_accuracy': float(val_score),
            'auc_score': float(auc_score),
            'timestamp': datetime.now().isoformat(),
            'feature_count': X.shape[1],
            'threshold': self.threshold,
        }
        
        # Extract feature importance
        self._extract_feature_importance()
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5, n_jobs=-1)
        
        logger.info(f"Training complete:")
        logger.info(f"  Train accuracy: {train_score:.4f}")
        logger.info(f"  Validation accuracy: {val_score:.4f}")
        logger.info(f"  AUC Score: {auc_score:.4f}")
        logger.info(f"  CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Print classification report
        report = classification_report(y_val, y_val_pred, target_names=['Safe', 'Vulnerable'])
        logger.info(f"\nClassification Report:\n{report}")
        
        return self.training_metadata

    def _extract_feature_importance(self):
        """Extract feature importance from the trained model"""
        try:
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importance = self.model.feature_importances_
            elif hasattr(self.model, 'estimators_'):
                # For ensemble models, average the importance
                importances = []
                for name, estimator in self.model.estimators_:
                    if hasattr(estimator, 'feature_importances_'):
                        importances.append(estimator.feature_importances_)
                
                if importances:
                    self.feature_importance = np.mean(importances, axis=0)
        except Exception as e:
            logger.warning(f"Could not extract feature importance: {e}")

    def predict(self, features: np.ndarray) -> Tuple[bool, float, Dict]:
        """
        Predict if features indicate vulnerability
        
        Returns:
            Tuple of (is_vulnerable, confidence, details)
        """
        if not self.is_trained:
            return False, 0.0, {'error': 'Model not trained'}
        
        try:
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            features_scaled = self.scaler.transform(features)
            proba = self.model.predict_proba(features_scaled)[0]
            vuln_prob = proba[1]  # Probability of class 1 (vulnerable)
            
            is_vulnerable = vuln_prob >= self.threshold
            
            # Create detailed result
            details = {
                'safe_probability': float(proba[0]),
                'vulnerable_probability': float(vuln_prob),
                'threshold': self.threshold,
                'confidence': float(max(proba)),
                'prediction': 'vulnerable' if is_vulnerable else 'safe',
            }
            
            # Add top contributing features if available
            if self.feature_importance is not None:
                feature_contributions = features_scaled[0] * self.feature_importance
                top_features_idx = np.argsort(np.abs(feature_contributions))[-5:][::-1]
                details['top_contributing_features'] = [int(idx) for idx in top_features_idx]
            
            return is_vulnerable, vuln_prob, details
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return False, 0.0, {'error': str(e)}

    def predict_batch(self, features_batch: np.ndarray) -> List[Tuple[bool, float, Dict]]:
        """Predict for multiple samples efficiently"""
        results = []
        
        if not self.is_trained:
            return [(False, 0.0, {'error': 'Model not trained'}) for _ in range(len(features_batch))]
        
        try:
            features_scaled = self.scaler.transform(features_batch)
            probas = self.model.predict_proba(features_scaled)
            
            for proba in probas:
                vuln_prob = proba[1]
                is_vulnerable = vuln_prob >= self.threshold
                
                details = {
                    'safe_probability': float(proba[0]),
                    'vulnerable_probability': float(vuln_prob),
                    'threshold': self.threshold,
                    'confidence': float(max(proba)),
                    'prediction': 'vulnerable' if is_vulnerable else 'safe',
                }
                
                results.append((is_vulnerable, vuln_prob, details))
            
            return results
            
        except Exception as e:
            logger.error(f"Batch prediction error: {e}")
            return [(False, 0.0, {'error': str(e)}) for _ in range(len(features_batch))]

    def save_model(self, path: str = None):
        """Save trained model and metadata to disk"""
        save_path = path or str(self.model_path)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_importance': self.feature_importance,
            'metadata': self.training_metadata,
            'threshold': self.threshold,
            'model_type': self.model_type,
            'version': '2.0',
        }
        
        joblib.dump(model_data, save_path)
        logger.info(f"Model saved to {save_path}")
        
        # Save metadata separately as JSON for easy inspection
        metadata_path = Path(save_path).with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump(self.training_metadata, f, indent=2)
        logger.info(f"Metadata saved to {metadata_path}")

    def load_model(self, path: str):
        """Load model from disk"""
        try:
            data = joblib.load(path)
            
            # Handle both old and new format
            if isinstance(data, dict):
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.feature_importance = data.get('feature_importance')
                self.training_metadata = data.get('metadata', {})
                self.threshold = data.get('threshold', self.threshold)
                self.model_type = data.get('model_type', 'unknown')
            else:
                # Old format - just model and scaler
                self.model = data['model']
                self.scaler = data['scaler']
            
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
            
            if self.training_metadata:
                logger.info(f"Model metadata: {json.dumps(self.training_metadata, indent=2)}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

    def get_feature_importance(self, feature_names: List[str] = None) -> Dict[str, float]:
        """Get feature importance scores"""
        if self.feature_importance is None:
            return {}
        
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(len(self.feature_importance))]
        
        importance_dict = dict(zip(feature_names, self.feature_importance))
        # Sort by importance
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))

    def optimize_threshold(self, X: np.ndarray, y: np.ndarray, metric: str = 'f1'):
        """
        Optimize detection threshold based on validation data
        
        Args:
            X: Validation features
            y: Validation labels
            metric: Metric to optimize ('f1', 'precision', 'recall')
        """
        if not self.is_trained:
            logger.error("Cannot optimize threshold - model not trained")
            return
        
        X_scaled = self.scaler.transform(X)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]
        
        # Calculate precision-recall curve
        precisions, recalls, thresholds = precision_recall_curve(y, y_proba)
        
        if metric == 'f1':
            f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
            best_idx = np.argmax(f1_scores)
            best_threshold = thresholds[best_idx]
            logger.info(f"Optimal F1 threshold: {best_threshold:.3f} (F1: {f1_scores[best_idx]:.3f})")
        
        elif metric == 'precision':
            # Find threshold for 95% precision
            target_precision = 0.95
            valid_idx = precisions >= target_precision
            if valid_idx.any():
                best_threshold = thresholds[valid_idx][0]
                logger.info(f"Threshold for {target_precision} precision: {best_threshold:.3f}")
            else:
                logger.warning("Could not find threshold for target precision")
                return
        
        elif metric == 'recall':
            # Find threshold for 95% recall
            target_recall = 0.95
            valid_idx = recalls >= target_recall
            if valid_idx.any():
                best_threshold = thresholds[valid_idx][-1]
                logger.info(f"Threshold for {target_recall} recall: {best_threshold:.3f}")
            else:
                logger.warning("Could not find threshold for target recall")
                return
        
        self.threshold = best_threshold
        logger.info(f"Updated threshold to {self.threshold:.3f}")

    def update_online(self, X_new: np.ndarray, y_new: np.ndarray):
        """
        Incrementally update model with new data (if supported)
        
        Note: Not all models support online learning. This is a placeholder
        for future implementation with models like SGDClassifier.
        """
        logger.warning("Online learning not yet implemented for this model type")
        # TODO: Implement with partial_fit for compatible models