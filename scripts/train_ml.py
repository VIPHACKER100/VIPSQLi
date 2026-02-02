import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.trainer import train_model

def main():
    print("--- VIP SQLi Scanner ML Trainer ---")
    success = train_model(min_samples=10) # Using small sample count for quick test
    if success:
        print("Success: Model trained and saved to ml/models/default.pkl")
    else:
        print("Failed: Not enough training data in the database.")
        print("Run 'python scripts/generate_training_data.py' first to initialize synthetic data.")

if __name__ == "__main__":
    main()
