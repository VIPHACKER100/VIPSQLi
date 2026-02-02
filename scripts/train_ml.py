"""
Enhanced ML Model Trainer for SQLi Detection
Includes improved training pipeline, validation, and model evaluation
"""
import sys
import os
import argparse
from typing import Tuple, Optional, Dict

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.trainer import train_model


class TrainingConfig:
    """Configuration for model training"""
    def __init__(
        self,
        min_samples: int = 100,
        test_size: float = 0.2,
        random_state: int = 42,
        verbose: bool = True
    ):
        self.min_samples = min_samples
        self.test_size = test_size
        self.random_state = random_state
        self.verbose = verbose


def print_banner():
    """Print training script banner"""
    print("=" * 70)
    print(" " * 15 + "VIP SQLi Scanner ML Trainer v2.0")
    print("=" * 70)


def print_section(title: str):
    """Print a section header"""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def validate_environment() -> bool:
    """
    Validate that the training environment is set up correctly
    
    Returns:
        bool: True if environment is valid, False otherwise
    """
    print_section("Environment Validation")
    
    checks_passed = True
    
    # Check if database module exists
    try:
        from database import get_session, init_db
        from database.models import MLTrainingData
        print("✓ Database modules found")
    except ImportError as e:
        print(f"✗ Database modules not found: {e}")
        checks_passed = False
    
    # Check if ML trainer module exists
    try:
        from ml.trainer import train_model
        print("✓ ML trainer module found")
    except ImportError as e:
        print(f"✗ ML trainer module not found: {e}")
        checks_passed = False
    
    # Check for required ML libraries
    required_libs = ['sklearn', 'numpy', 'joblib']
    for lib in required_libs:
        try:
            __import__(lib)
            print(f"✓ {lib} library available")
        except ImportError:
            print(f"✗ {lib} library not found - install with: pip install {lib}")
            checks_passed = False
    
    return checks_passed


def check_training_data() -> Tuple[bool, int]:
    """
    Check if sufficient training data is available
    
    Returns:
        Tuple[bool, int]: (data_available, sample_count)
    """
    print_section("Training Data Check")
    
    try:
        from database import get_session
        from database.models import MLTrainingData
        
        session = get_session()
        total_samples = session.query(MLTrainingData).filter_by(verified=True).count()
        
        if total_samples == 0:
            print("✗ No training data found in database")
            print("\n  To generate synthetic training data, run:")
            print("  python scripts/generate_training_data.py")
            return False, 0
        
        # Count samples by label
        safe_count = session.query(MLTrainingData).filter_by(
            verified=True, label=0
        ).count()
        vuln_count = session.query(MLTrainingData).filter_by(
            verified=True, label=1
        ).count()
        
        print(f"✓ Found {total_samples} verified training samples")
        print(f"  - Safe (label=0): {safe_count} samples ({safe_count/total_samples*100:.1f}%)")
        print(f"  - Vulnerable (label=1): {vuln_count} samples ({vuln_count/total_samples*100:.1f}%)")
        
        # Check for class imbalance
        if vuln_count > 0:
            imbalance_ratio = safe_count / vuln_count
            if imbalance_ratio > 5.0:
                print(f"\n⚠ Warning: High class imbalance detected (ratio: {imbalance_ratio:.2f}:1)")
                print("  Consider generating more vulnerable samples for better balance")
            elif imbalance_ratio < 1.5:
                print(f"\n✓ Good class balance (ratio: {imbalance_ratio:.2f}:1)")
        
        session.close()
        return True, total_samples
        
    except Exception as e:
        print(f"✗ Error checking training data: {e}")
        return False, 0


def train_with_config(config: TrainingConfig) -> bool:
    """
    Train the model with specified configuration
    
    Args:
        config: TrainingConfig object with training parameters
        
    Returns:
        bool: True if training successful, False otherwise
    """
    print_section("Model Training")
    
    print(f"Training configuration:")
    print(f"  - Minimum samples: {config.min_samples}")
    print(f"  - Test set size: {config.test_size * 100:.0f}%")
    print(f"  - Random state: {config.random_state}")
    print(f"  - Verbose: {config.verbose}")
    
    print("\nStarting training process...")
    
    try:
        success = train_model(
            min_samples=config.min_samples,
            test_size=config.test_size,
            random_state=config.random_state
        )
        
        if success:
            print_section("Training Results")
            print("✓ Model training completed successfully")
            print("✓ Model saved to: ml/models/default.pkl")
            print("\nThe model is now ready to use for SQLi detection!")
            print("\nNext steps:")
            print("  1. Test the model with sample inputs")
            print("  2. Deploy the model to your scanner")
            print("  3. Monitor performance and retrain as needed")
            return True
        else:
            print_section("Training Failed")
            print("✗ Model training failed")
            print("\nPossible issues:")
            print("  - Insufficient training data")
            print("  - Data quality problems")
            print("  - Configuration errors")
            return False
            
    except Exception as e:
        print_section("Training Error")
        print(f"✗ Unexpected error during training: {e}")
        print("\nPlease check:")
        print("  - Database connection")
        print("  - Training data quality")
        print("  - System resources")
        return False


def main():
    """Main training function with argument parsing"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Train SQLi detection ML model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train with default settings
  python train_ml.py
  
  # Train with custom minimum samples
  python train_ml.py --min-samples 500
  
  # Train with custom test split
  python train_ml.py --test-size 0.3
  
  # Skip environment checks (not recommended)
  python train_ml.py --skip-checks
        """
    )
    
    parser.add_argument(
        '--min-samples',
        type=int,
        default=100,
        help='Minimum number of samples required for training (default: 100)'
    )
    
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Proportion of data to use for testing (default: 0.2)'
    )
    
    parser.add_argument(
        '--random-state',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    
    parser.add_argument(
        '--skip-checks',
        action='store_true',
        help='Skip environment validation checks'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Reduce output verbosity'
    )
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Validate environment
    if not args.skip_checks:
        if not validate_environment():
            print("\n✗ Environment validation failed!")
            print("Fix the issues above or use --skip-checks to continue anyway")
            return 1
    
    # Check training data availability
    if not args.skip_checks:
        data_available, sample_count = check_training_data()
        if not data_available:
            print("\n✗ No training data available!")
            return 1
        
        if sample_count < args.min_samples:
            print(f"\n✗ Insufficient training data!")
            print(f"  Found: {sample_count} samples")
            print(f"  Required: {args.min_samples} samples")
            print("\n  Generate more data with:")
            print("  python scripts/generate_training_data.py")
            return 1
    
    # Create training configuration
    config = TrainingConfig(
        min_samples=args.min_samples,
        test_size=args.test_size,
        random_state=args.random_state,
        verbose=not args.quiet
    )
    
    # Train the model
    success = train_with_config(config)
    
    # Print final status
    if not args.quiet:
        print("\n" + "=" * 70)
        if success:
            print(" " * 20 + "✓ TRAINING COMPLETE")
        else:
            print(" " * 20 + "✗ TRAINING FAILED")
        print("=" * 70 + "\n")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())