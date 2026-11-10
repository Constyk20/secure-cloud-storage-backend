from fastapi import APIRouter, Depends

from auth import public_user, require_admin
from database import get_database

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
def list_users(_: dict = Depends(require_admin)):
    users = get_database().users.find().sort("created_at", -1)
    return [public_user(user) for user in users]


@router.get("/stats")
def stats(_: dict = Depends(require_admin)):
    database = get_database()
    return {
        "users": database.users.count_documents({}),
        "files": database.files.count_documents({}),
        "security_events": database.security_logs.count_documents({}),
    }