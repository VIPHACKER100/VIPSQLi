"""
ML Module for SQL Injection Detection

This module provides machine learning capabilities for detecting SQL injection
vulnerabilities through pattern recognition and behavioral analysis.

Components:
- MLDetector: Core ML model for vulnerability detection
- FeatureExtractor: Advanced feature engineering from URLs and responses
- ModelTrainer: Training pipeline with model comparison and optimization

Version: 2.0
"""

from .detector import MLDetector
from .features import FeatureExtractor
from .trainer import ModelTrainer, train_model, train_advanced

__all__ = [
    'MLDetector',
    'FeatureExtractor',
    'ModelTrainer',
    'train_model',
    'train_advanced',
]

__version__ = '2.0.0'