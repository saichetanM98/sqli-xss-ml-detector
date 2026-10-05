"""Database service manager for MongoDB persistence with graceful fallback."""

import logging
from typing import Optional
from gateway.config import Config

logger = logging.getLogger(__name__)

_mongo_client = None
_db = None


def get_db():
    """
    Retrieve MongoDB database instance or return None if offline.
    Uses a 2-second timeout to avoid hanging if the service is not started.
    """
    global _mongo_client, _db
    if _db is not None:
        return _db

    try:
        import pymongo
        _mongo_client = pymongo.MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=2000)
        # Test connection with a quick ping
        _mongo_client.admin.command("ping")
        _db = _mongo_client.get_database()
        logger.info("Connected to MongoDB at %s", Config.MONGO_URI)
        return _db
    except Exception as e:
        logger.warning("MongoDB not reachable (%s). Falling back to in-memory storage.", e)
        return None


def get_db_status() -> dict:
    """Return current database connection status for health monitoring."""
    db = get_db()
    if db is not None:
        return {"status": "connected", "type": "mongodb"}
    return {"status": "offline_fallback", "type": "in-memory"}
