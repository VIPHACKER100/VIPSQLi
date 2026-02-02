from database import get_session
from database.models import MLTrainingData
from ml.detector import MLDetector
from ml.features import FeatureExtractor
import numpy as np
import logging
from pathlib import Path
from typing import Optional, Dict, List
import json
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger("vipsqli.trainer")

class ModelTrainer:
    """
    Enhanced model trainer with comprehensive training pipeline
    
    Improvements:
    - Data validation and preprocessing
    - Multiple model training and comparison
    - Hyperparameter tuning
    - Training history tracking
    - Model performance visualization
    - Cross-validation
    - Model versioning
    """
    
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent / "models"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.feature_extractor = FeatureExtractor()
        self.training_history = []
    
    def validate_data(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Validate training data quality"""
        logger.info("Validating training data...")
        
        # Check for NaN or infinite values
        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            logger.error("Data contains NaN or infinite values")
            return False
        
        # Check class balance
        unique, counts = np.unique(y, return_counts=True)
        class_distribution = dict(zip(unique, counts))
        logger.info(f"Class distribution: {class_distribution}")
        
        # Warn if severely imbalanced
        if len(unique) == 2:
            ratio = min(counts) / max(counts)
            if ratio < 0.1:
                logger.warning(f"Severe class imbalance detected: {ratio:.2%}")
                logger.warning("Consider using techniques like SMOTE or adjusting class weights")
        
        # Check feature variance
        feature_vars = np.var(X, axis=0)
        zero_var_features = np.sum(feature_vars == 0)
        if zero_var_features > 0:
            logger.warning(f"{zero_var_features} features have zero variance")
        
        logger.info("Data validation complete")
        return True
    
    def prepare_data(self, min_samples: int = 100) -> Optional[tuple]:
        """
        Fetch and prepare training data from database
        
        Args:
            min_samples: Minimum number of samples required
            
        Returns:
            Tuple of (X, y) or None if insufficient data
        """
        session = get_session()
        
        try:
            # Fetch verified training data
            # In production, filter by verified=True
            data = session.query(MLTrainingData).all()
            
            if len(data) < min_samples:
                logger.warning(f"Insufficient data: need {min_samples}, have {len(data)}")
                return None
            
            logger.info(f"Loaded {len(data)} training samples from database")
            
            # Extract features and labels
            X = np.array([d.features for d in data])
            y = np.array([d.label for d in data])
            
            # Validate data
            if not self.validate_data(X, y):
                return None
            
            return X, y
            
        except Exception as e:
            logger.error(f"Error preparing data: {e}")
            return None
        finally:
            session.close()
    
    def train_single_model(
        self,
        X: np.ndarray,
        y: np.ndarray,
        model_type: str = 'ensemble',
        threshold: float = 0.7,
        validation_split: float = 0.2,
        optimize_threshold: bool = True
    ) -> Optional[MLDetector]:
        """
        Train a single model
        
        Args:
            X: Feature matrix
            y: Labels
            model_type: Type of model to train
            threshold: Detection threshold
            validation_split: Fraction for validation
            optimize_threshold: Whether to optimize threshold
            
        Returns:
            Trained MLDetector or None
        """
        logger.info(f"Training {model_type} model...")
        
        detector = MLDetector(model_type=model_type, threshold=threshold)
        
        # Train model
        metadata = detector.train(X, y, validation_split=validation_split)
        
        # Optimize threshold if requested
        if optimize_threshold:
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42, stratify=y
            )
            detector.optimize_threshold(X_val, y_val, metric='f1')
        
        # Add model type to metadata
        metadata['model_type'] = model_type
        self.training_history.append(metadata)
        
        return detector
    
    def compare_models(
        self,
        X: np.ndarray,
        y: np.ndarray,
        model_types: List[str] = None,
        validation_split: float = 0.2
    ) -> Dict[str, Dict]:
        """
        Train and compare multiple model types
        
        Args:
            X: Feature matrix
            y: Labels
            model_types: List of model types to compare
            validation_split: Fraction for validation
            
        Returns:
            Dictionary of model performances
        """
        if model_types is None:
            model_types = ['random_forest', 'gradient_boosting', 'ensemble']
            # Add XGBoost if available
            try:
                import xgboost
                model_types.append('xgboost')
            except ImportError:
                pass
        
        logger.info(f"Comparing {len(model_types)} model types...")
        
        results = {}
        
        for model_type in model_types:
            try:
                detector = self.train_single_model(
                    X, y, 
                    model_type=model_type,
                    validation_split=validation_split,
                    optimize_threshold=False
                )
                
                if detector:
                    results[model_type] = detector.training_metadata
                    logger.info(f"{model_type}: Val Acc={detector.training_metadata['validation_accuracy']:.4f}, "
                              f"AUC={detector.training_metadata['auc_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Error training {model_type}: {e}")
        
        # Save comparison results
        comparison_path = self.output_dir / f"model_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(comparison_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Model comparison saved to {comparison_path}")
        
        return results
    
    def visualize_performance(self, detector: MLDetector, X_val: np.ndarray, y_val: np.ndarray):
        """Create performance visualization"""
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            
            # Get predictions
            X_val_scaled = detector.scaler.transform(X_val)
            y_pred = detector.model.predict(X_val_scaled)
            y_proba = detector.model.predict_proba(X_val_scaled)[:, 1]
            
            # Create confusion matrix
            cm = confusion_matrix(y_val, y_pred)
            
            fig, axes = plt.subplots(1, 2, figsize=(12, 5))
            
            # Plot confusion matrix
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0])
            axes[0].set_title('Confusion Matrix')
            axes[0].set_ylabel('True Label')
            axes[0].set_xlabel('Predicted Label')
            
            # Plot probability distribution
            axes[1].hist(y_proba[y_val == 0], bins=50, alpha=0.5, label='Safe', color='green')
            axes[1].hist(y_proba[y_val == 1], bins=50, alpha=0.5, label='Vulnerable', color='red')
            axes[1].axvline(detector.threshold, color='black', linestyle='--', label='Threshold')
            axes[1].set_xlabel('Vulnerability Probability')
            axes[1].set_ylabel('Count')
            axes[1].set_title('Prediction Distribution')
            axes[1].legend()
            
            plt.tight_layout()
            
            # Save plot
            plot_path = self.output_dir / f"performance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(plot_path)
            plt.close()
            
            logger.info(f"Performance visualization saved to {plot_path}")
            
        except Exception as e:
            logger.warning(f"Could not create visualization: {e}")
    
    def train_and_save_best(
        self,
        min_samples: int = 100,
        compare_models: bool = True,
        save_path: str = None
    ) -> bool:
        """
        Complete training pipeline: load data, train, compare, save best
        
        Args:
            min_samples: Minimum samples required
            compare_models: Whether to compare multiple model types
            save_path: Path to save the best model
            
        Returns:
            True if successful, False otherwise
        """
        # Prepare data
        data = self.prepare_data(min_samples)
        if data is None:
            return False
        
        X, y = data
        
        # Split data for final validation
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        best_detector = None
        best_score = 0.0
        
        if compare_models:
            # Compare multiple models
            results = self.compare_models(X_train, y_train)
            
            # Find best model
            best_model_type = max(results.keys(), key=lambda k: results[k]['auc_score'])
            logger.info(f"Best model type: {best_model_type}")
            
            # Train best model on full training set with threshold optimization
            best_detector = self.train_single_model(
                X_train, y_train,
                model_type=best_model_type,
                optimize_threshold=True
            )
        else:
            # Train single ensemble model
            best_detector = self.train_single_model(
                X_train, y_train,
                model_type='ensemble',
                optimize_threshold=True
            )
        
        if best_detector is None:
            logger.error("Failed to train model")
            return False
        
        # Visualize performance
        self.visualize_performance(best_detector, X_val, y_val)
        
        # Get feature importance
        feature_importance = best_detector.get_feature_importance(
            self.feature_extractor.feature_names
        )
        
        logger.info("Top 10 most important features:")
        for i, (feature, importance) in enumerate(list(feature_importance.items())[:10], 1):
            logger.info(f"  {i}. {feature}: {importance:.4f}")
        
        # Save model
        if save_path is None:
            save_path = self.output_dir / "default.pkl"
        
        best_detector.save_model(str(save_path))
        
        logger.info(f"Training complete! Model saved to {save_path}")
        logger.info(f"Final metrics: Val Acc={best_detector.training_metadata['validation_accuracy']:.4f}, "
                   f"AUC={best_detector.training_metadata['auc_score']:.4f}")
        
        return True
    
    def save_training_history(self):
        """Save training history to file"""
        history_path = self.output_dir / "training_history.json"
        
        with open(history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
        
        logger.info(f"Training history saved to {history_path}")


# Convenience function for backward compatibility
def train_model(min_samples: int = 100) -> bool:
    """
    Legacy training function - trains and saves best model
    
    Args:
        min_samples: Minimum number of samples required
        
    Returns:
        True if successful, False otherwise
    """
    trainer = ModelTrainer()
    success = trainer.train_and_save_best(min_samples=min_samples)
    trainer.save_training_history()
    return success


# Advanced training function
def train_advanced(
    min_samples: int = 100,
    compare_models: bool = True,
    output_dir: str = None
) -> bool:
    """
    Advanced training with model comparison and analysis
    
    Args:
        min_samples: Minimum samples required
        compare_models: Whether to compare multiple model types
        output_dir: Directory to save outputs
        
    Returns:
        True if successful, False otherwise
    """
    trainer = ModelTrainer(output_dir=output_dir)
    success = trainer.train_and_save_best(
        min_samples=min_samples,
        compare_models=compare_models
    )
    trainer.save_training_history()
    return success


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description='Train SQL injection detection model')
    parser.add_argument('--min-samples', type=int, default=100, help='Minimum training samples')
    parser.add_argument('--compare', action='store_true', help='Compare multiple models')
    parser.add_argument('--output-dir', type=str, help='Output directory for models')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    success = train_advanced(
        min_samples=args.min_samples,
        compare_models=args.compare,
        output_dir=args.output_dir
    )
    
    if success:
        logger.info("Training completed successfully!")
    else:
        logger.error("Training failed!")
        exit(1)