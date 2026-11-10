import base64
import uuid
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import Response

from auth import get_current_user, unwrap_private_key
from database import get_database
from encryption import (
    decrypt_file,
    encrypt_file,
    generate_aes_key,
    generate_nonce,
    load_public_key,
    unwrap_aes_key,
    wrap_aes_key,
)
from integrity import metadata_hmac, sha256_digest, verify_metadata_hmac, verify_plaintext
from storage import get_storage

router = APIRouter(prefix="/files", tags=["files"])

MAX_UPLOAD_BYTES = 20 * 1024 * 1024


def log_event(event: str, user_id: str, details: str) -> None:
    get_database().security_logs.insert_one(
        {
            "event": event,
            "user_id": user_id,
            "details": details,
            "created_at": datetime.now(timezone.utc),
        }
    )


def _owned_file(file_id: str, user: dict) -> dict:
    try:
        object_id = ObjectId(file_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    document = get_database().files.find_one(
        {"_id": object_id, "owner_id": str(user["_id"])}
    )
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return document


def public_file(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "filename": document["filename"],
        "content_type": document["content_type"],
        "size": document["size"],
        "uploaded_at": document["uploaded_at"].isoformat(),
        "encryption_status": "AES-256-GCM",
        "integrity_status": document.get("integrity_status", "verified_at_upload"),
    }


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    plaintext = await file.read(MAX_UPLOAD_BYTES + 1)
    if not plaintext:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")
    if len(plaintext) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds 20 MB")

    owner_id = str(user["_id"])
    filename = (file.filename or "upload.bin").replace("\\", "/").split("/")[-1][:180]
    content_type = file.content_type or "application/octet-stream"
    storage_path = f"{owner_id}/{uuid.uuid4().hex}.bin"

    digest = sha256_digest(plaintext)
    aes_key = generate_aes_key()
    nonce = generate_nonce()
    ciphertext = encrypt_file(plaintext, aes_key, nonce)
    wrapped_key = wrap_aes_key(aes_key, load_public_key(user["public_key_pem"]))

    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    wrapped_b64 = base64.b64encode(wrapped_key).decode("ascii")
    tag = metadata_hmac(owner_id, storage_path, digest, nonce_b64, wrapped_b64)

    storage = get_storage()
    storage.upload(
        storage_path,
        ciphertext,
        {"content-type": "application/octet-stream", "upsert": "false"},
    )

    document = {
        "owner_id": owner_id,
        "filename": filename,
        "content_type": content_type,
        "size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "storage_path": storage_path,
        "nonce": nonce_b64,
        "wrapped_aes_key": wrapped_b64,
        "sha256": digest,
        "metadata_hmac": tag,
        "integrity_status": "verified_at_upload",
        "uploaded_at": datetime.now(timezone.utc),
    }

    try:
        result = get_database().files.insert_one(document)
    except Exception:
        storage.remove([storage_path])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not save file metadata")

    document["_id"] = result.inserted_id
    log_event("file_uploaded", owner_id, filename)
    return public_file(document)


@router.get("")
def list_files(user: dict = Depends(get_current_user)):
    cursor = get_database().files.find({"owner_id": str(user["_id"])}).sort("uploaded_at", -1)
    return [public_file(document) for document in cursor]


@router.get("/{file_id}")
def get_file(file_id: str, user: dict = Depends(get_current_user)):
    return public_file(_owned_file(file_id, user))


@router.get("/{file_id}/download")
def download_file(file_id: str, user: dict = Depends(get_current_user)):
    document = _owned_file(file_id, user)
    owner_id = str(user["_id"])

    if not verify_metadata_hmac(
        owner_id,
        document["storage_path"],
        document["sha256"],
        document["nonce"],
        document["wrapped_aes_key"],
        document["metadata_hmac"],
    ):
        log_event("integrity_failed", owner_id, "metadata hmac mismatch")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity verification failed")

    ciphertext = get_storage().download(document["storage_path"])
    private_key = unwrap_private_key(user["wrapped_private_key"])
    aes_key = unwrap_aes_key(base64.b64decode(document["wrapped_aes_key"]), private_key)

    try:
        plaintext = decrypt_file(ciphertext, aes_key, base64.b64decode(document["nonce"]))
    except Exception:
        log_event("integrity_failed", owner_id, "aes-gcm authentication failed")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity verification failed")

    if not verify_plaintext(plaintext, document["sha256"]):
        log_event("integrity_failed", owner_id, "sha256 mismatch")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity verification failed")

    log_event("file_downloaded", owner_id, document["filename"])
    return Response(
        content=plaintext,
        media_type=document["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{document["filename"]}"'},
    )


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(file_id: str, user: dict = Depends(get_current_user)):
    document = _owned_file(file_id, user)
    owner_id = str(user["_id"])
    get_storage().remove([document["storage_path"]])
    get_database().files.delete_one({"_id": document["_id"], "owner_id": owner_id})
    log_event("file_deleted", owner_id, document["filename"])