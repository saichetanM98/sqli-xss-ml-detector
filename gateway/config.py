"""Configuration settings, risk weights, and thresholds."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base application and gateway configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    PORT = int(os.getenv("PORT", 5000))
    DEBUG = os.getenv("FLASK_ENV", "development") == "development"

    # Database
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/adaptive_security_gateway")
    DATABASE_URL = os.getenv("DATABASE_URL", "")

    # ML Artifacts
    MODEL_PATH = os.getenv("MODEL_PATH", "ml/artifacts/best_model.pt")
    VOCAB_PATH = os.getenv("VOCAB_PATH", "ml/artifacts/vocab.json")

    # Decision Thresholds
    RISK_THRESHOLD_BLOCK = int(os.getenv("RISK_THRESHOLD_BLOCK", 80))
    RISK_THRESHOLD_MONITOR = int(os.getenv("RISK_THRESHOLD_MONITOR", 40))
    HIGH_CONFIDENCE_THRESHOLD = float(os.getenv("HIGH_CONFIDENCE_THRESHOLD", 0.90))

    # Rate Limiting
    MAX_REQUEST_RATE_PER_MINUTE = 60
