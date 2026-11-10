from fastapi import APIRouter, Depends

from auth import get_current_user, require_admin
from database import get_database

router = APIRouter(prefix="/security", tags=["security"])


def _public_log(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "event": document["event"],
        "user_id": document["user_id"],
        "details": document["details"],
        "created_at": document["created_at"].isoformat(),
    }


@router.get("/status")
def security_status(user: dict = Depends(get_current_user)):
    database = get_database()
    owner_id = str(user["_id"])
    file_count = database.files.count_documents({"owner_id": owner_id})
    storage_bytes = 0
    for document in database.files.find({"owner_id": owner_id}, {"size": 1}):
        storage_bytes += int(document.get("size", 0))

    return {
        "encryption": "AES-256-GCM",
        "key_wrapping": "RSA-3072-OAEP-SHA256",
        "integrity": "SHA-256 + HMAC-SHA256 + AES-GCM tag",
        "file_count": file_count,
        "encrypted_file_count": file_count,
        "storage_bytes": storage_bytes,
        "backend_can_decrypt": True,
    }


@router.get("/logs")
def security_logs(user: dict = Depends(get_current_user)):
    query = {} if user.get("role") == "admin" else {"user_id": str(user["_id"])}
    cursor = get_database().security_logs.find(query).sort("created_at", -1).limit(100)
    return [_public_log(document) for document in cursor]


@router.get("/admin/check")
def admin_check(_: dict = Depends(require_admin)):
    return {"admin": True}