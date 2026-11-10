from pymongo import MongoClient, ASCENDING
from pymongo.database import Database

from config import get_settings

settings = get_settings()
client = MongoClient(settings.MONGODB_URI)
db: Database = client[settings.DATABASE_NAME]


def get_database() -> Database:
    return db


def ensure_indexes() -> None:
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.files.create_index([("owner_id", ASCENDING)])
    db.security_logs.create_index([("created_at", ASCENDING)])

    # Google Drive OAuth (Phase 1)
    db.google_oauth_states.create_index([("state_hash", ASCENDING)], unique=True)
    db.google_oauth_states.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    db.google_connections.create_index([("user_id", ASCENDING)], unique=True)
    db.google_connections.create_index([("google_sub", ASCENDING)], unique=True)


def close_database_connection() -> None:
    client.close()