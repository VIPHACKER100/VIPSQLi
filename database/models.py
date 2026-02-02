from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_urls = Column(Integer)
    vulnerable = Column(Integer)
    safe = Column(Integer)
    config = Column(JSON)

class URLResult(Base):
    __tablename__ = 'url_results'
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36))
    url = Column(Text)
    verdict = Column(String(20))
    risk = Column(String(20))
    ml_score = Column(Float)
    features = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)

class MLTrainingData(Base):
    __tablename__ = 'ml_training_data'
    id = Column(Integer, primary_key=True)
    url = Column(Text)
    features = Column(JSON)
    label = Column(Integer)  # 0=safe, 1=vulnerable
    confidence = Column(Float)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
