"""Google Drive storage for encrypted file contents.

Only ciphertext is ever sent to Drive. Files are created inside an app folder
("Secure Cloud Storage") with a random name, using the least-privilege drive.file scope.

PUT /google/storage  (Bearer) {"enabled": bool}  -> turn Drive storage on/off for new uploads
"""
import hashlib
import time
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import get_current_user
from database import get_database
from google_oauth import (
    api_error,
    get_valid_access_token,
    log_security_event,
    mark_reauth_required,
)

router = APIRouter(prefix="/google/storage", tags=["google"])

FILES_URL = "https://www.googleapis.com/drive/v3/files"
UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files"
UPLOAD_HOST_PREFIX = "https://www.googleapis.com/"
FOLDER_NAME = "Secure Cloud Storage"
FOLDER_MIME = "application/vnd.google-apps.folder"

API_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
UPLOAD_TIMEOUT = httpx.Timeout(120.0, connect=10.0)
UPLOAD_ATTEMPTS = 5
RETRYABLE_STATUS = {500, 502, 503, 504}
RATE_LIMIT_REASONS = {
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "dailyLimitExceeded",
    "sharingRateLimitExceeded",
}


# ------------------------------------------------------------------ error mapping

def _error_reasons(response: httpx.Response) -> set[str]:
    try:
        error = response.json().get("error", {})
    except (ValueError, AttributeError):
        return set()
    if not isinstance(error, dict):
        return set()
    reasons = {item.get("reason") for item in error.get("errors", []) if isinstance(item, dict)}
    reasons |= {item.get("reason") for item in error.get("details", []) if isinstance(item, dict)}
    return {reason for reason in reasons if reason}


def _raise_for_drive(response: httpx.Response) -> None:
    """Translate a failed Drive response into an HTTPException with a stable detail.code."""
    code = response.status_code
    reasons = _error_reasons(response)

    if code == 404:
        raise api_error("drive_file_missing", "The file was not found in Google Drive. It may have been deleted there.", 404)
    if reasons & {"accessNotConfigured", "SERVICE_DISABLED"}:
        raise api_error("drive_api_disabled", "The Google Drive API is not enabled for this app's Google Cloud project.", 503)
    if "storageQuotaExceeded" in reasons:
        raise api_error("drive_quota_exceeded", "Your Google Drive storage is full. Free up space and try again.", 507)
    if code == 429 or reasons & RATE_LIMIT_REASONS:
        raise api_error("drive_rate_limited", "Google Drive is rate limiting requests. Try again shortly.", 429)
    if code == 403:
        raise api_error("drive_access_denied", "Google Drive refused access. Try reconnecting Google Drive.", 409)
    if code >= 500:
        raise api_error("drive_unavailable", "Google Drive is temporarily unavailable. Try again shortly.", 503)
    raise api_error("drive_error", "Google Drive returned an unexpected error.", 502)


# ---------------------------------------------------------------------- HTTP helper

def _drive_call(user_id: str, method: str, url: str, *, headers: dict | None = None, **kwargs) -> httpx.Response:
    """Authenticated Drive request. On a 401 it forces one token refresh and retries once."""
    for attempt in range(2):
        token = get_valid_access_token(user_id, force_refresh=attempt == 1)
        merged = {"Authorization": f"Bearer {token}", **(headers or {})}
        try:
            response = httpx.request(method, url, headers=merged, timeout=API_TIMEOUT, **kwargs)
        except httpx.HTTPError:
            raise api_error("google_unreachable", "Could not reach Google Drive. Please try again shortly.", 503)
        if response.status_code != 401:
            return response
    mark_reauth_required(user_id)
    raise api_error("google_reauth_required", "Google Drive authorization expired or was revoked. Please reconnect.")


def _check_account(user_id: str, expected_sub: str) -> None:
    connection = get_database().google_connections.find_one({"user_id": user_id})
    if connection is None:
        raise api_error("google_not_connected", "Google Drive is not connected")
    if connection.get("google_sub") != expected_sub:
        raise api_error(
            "google_wrong_account",
            "This file is stored in a different Google account than the one connected now.",
        )


# -------------------------------------------------------------------------- folder

def _ensure_folder(user_id: str) -> str:
    database = get_database()
    connection = database.google_connections.find_one({"user_id": user_id})
    if connection is None:
        raise api_error("google_not_connected", "Google Drive is not connected")

    folder_id = connection.get("drive_folder_id")
    if folder_id:
        response = _drive_call(
            user_id, "GET", f"{FILES_URL}/{quote(folder_id, safe='')}", params={"fields": "id,trashed"}
        )
        if response.status_code == 200 and not response.json().get("trashed"):
            return folder_id
        if response.status_code not in (200, 404):
            _raise_for_drive(response)
        # folder was deleted or trashed in Drive: create a fresh one

    response = _drive_call(
        user_id,
        "POST",
        FILES_URL,
        params={"fields": "id"},
        json={"name": FOLDER_NAME, "mimeType": FOLDER_MIME},
    )
    if response.status_code not in (200, 201):
        _raise_for_drive(response)
    folder_id = response.json()["id"]
    database.google_connections.update_one({"user_id": user_id}, {"$set": {"drive_folder_id": folder_id}})
    return folder_id


# ------------------------------------------------------------------ resumable upload

def _query_upload(session_uri: str, total: int):
    """Ask Google how much of the upload it has. Returns (finished_file_json | None, offset | None)."""
    try:
        response = httpx.put(
            session_uri,
            content=b"",
            headers={"Content-Range": f"bytes */{total}"},
            timeout=API_TIMEOUT,
        )
    except httpx.HTTPError:
        return None, None
    if response.status_code in (200, 201):
        return response.json(), total
    if response.status_code == 308:
        received = response.headers.get("Range")
        if not received:
            return None, 0
        try:
            return None, int(received.split("-")[-1]) + 1
        except ValueError:
            return None, 0
    if response.status_code in (404, 410):
        raise api_error("drive_upload_interrupted", "The upload session expired. Please try again.", 503)
    return None, None


def _send_resumable(session_uri: str, data: bytes) -> dict:
    total = len(data)
    offset = 0
    for attempt in range(UPLOAD_ATTEMPTS):
        response = None
        headers = {"Content-Type": "application/octet-stream"}
        if offset:
            headers["Content-Range"] = f"bytes {offset}-{total - 1}/{total}"
        try:
            response = httpx.put(session_uri, content=data[offset:], headers=headers, timeout=UPLOAD_TIMEOUT)
        except httpx.HTTPError:
            response = None

        if response is not None:
            if response.status_code in (200, 201):
                return response.json()
            if response.status_code not in RETRYABLE_STATUS:
                _raise_for_drive(response)

        # Interrupted or transient failure: back off, ask Google what it has, then resume.
        time.sleep(min(2**attempt, 8))
        finished, new_offset = _query_upload(session_uri, total)
        if finished is not None:
            return finished
        if new_offset is not None:
            offset = new_offset

    raise api_error("drive_upload_interrupted", "Upload to Google Drive was interrupted. Please try again.", 503)


def _verify_upload(user_id: str, file_id: str, data: bytes) -> bool:
    response = _drive_call(
        user_id, "GET", f"{FILES_URL}/{quote(file_id, safe='')}", params={"fields": "id,size,md5Checksum"}
    )
    if response.status_code != 200:
        _raise_for_drive(response)
    meta = response.json()
    size_ok = str(meta.get("size", "")) == str(len(data))
    md5 = meta.get("md5Checksum")
    md5_ok = md5 is None or md5 == hashlib.md5(data, usedforsecurity=False).hexdigest()
    return size_ok and md5_ok


# ------------------------------------------------------------------------ public API

def upload_ciphertext(user_id: str, name: str, data: bytes) -> dict:
    """Upload encrypted bytes to the user's Drive. Returns {"drive_file_id", "google_account_sub"}."""
    folder_id = _ensure_folder(user_id)

    session_uri = ""
    for attempt in range(2):
        init = _drive_call(
            user_id,
            "POST",
            UPLOAD_URL,
            params={"uploadType": "resumable"},
            headers={
                "X-Upload-Content-Type": "application/octet-stream",
                "X-Upload-Content-Length": str(len(data)),
            },
            json={"name": name, "parents": [folder_id], "mimeType": "application/octet-stream"},
        )
        if init.status_code == 200:
            session_uri = init.headers.get("Location", "")
            break
        if init.status_code == 404:
            if attempt == 1:
                raise api_error("drive_error", "Could not create the file in Google Drive.", 502)
            # Stored folder vanished: forget it and create a new one.
            get_database().google_connections.update_one({"user_id": user_id}, {"$unset": {"drive_folder_id": ""}})
            folder_id = _ensure_folder(user_id)
            continue
        _raise_for_drive(init)

    if not session_uri.startswith(UPLOAD_HOST_PREFIX):
        raise api_error("drive_error", "Google Drive did not start the upload session.", 502)

    created = _send_resumable(session_uri, data)
    file_id = created.get("id")
    if not file_id:
        raise api_error("drive_error", "Google Drive did not return a file ID.", 502)

    try:
        verified = _verify_upload(user_id, file_id, data)
    except HTTPException:
        discard_ciphertext(user_id, file_id)
        raise
    if not verified:
        discard_ciphertext(user_id, file_id)
        raise api_error("drive_upload_failed", "Google Drive did not confirm the uploaded file. Please try again.", 502)

    connection = get_database().google_connections.find_one({"user_id": user_id}, {"google_sub": 1})
    return {"drive_file_id": file_id, "google_account_sub": connection["google_sub"]}


def download_ciphertext(user_id: str, drive_file_id: str, expected_sub: str) -> bytes:
    _check_account(user_id, expected_sub)
    response = _drive_call(user_id, "GET", f"{FILES_URL}/{quote(drive_file_id, safe='')}", params={"alt": "media"})
    if response.status_code != 200:
        _raise_for_drive(response)
    return response.content


def delete_ciphertext(user_id: str, drive_file_id: str, expected_sub: str) -> None:
    _check_account(user_id, expected_sub)
    response = _drive_call(user_id, "DELETE", f"{FILES_URL}/{quote(drive_file_id, safe='')}")
    if response.status_code in (200, 204, 404):  # 404: already gone, treat as success
        return
    _raise_for_drive(response)


def discard_ciphertext(user_id: str, drive_file_id: str) -> None:
    """Best-effort cleanup used when a later step failed. Never raises."""
    try:
        _drive_call(user_id, "DELETE", f"{FILES_URL}/{quote(drive_file_id, safe='')}")
    except Exception:
        pass


# ------------------------------------------------------------------ storage preference

class StoragePreference(BaseModel):
    enabled: bool


@router.put("")
def set_storage_preference(body: StoragePreference, user: dict = Depends(get_current_user)):
    user_id = str(user["_id"])
    database = get_database()
    connection = database.google_connections.find_one({"user_id": user_id})

    if body.enabled:
        if connection is None:
            raise api_error("google_not_connected", "Connect Google Drive first.")
        # Prove the whole path works before turning it on: refresh token, Drive API, folder.
        get_valid_access_token(user_id, force_refresh=True)
        _ensure_folder(user_id)
        database.google_connections.update_one(
            {"user_id": user_id},
            {"$set": {"storage_enabled": True, "updated_at": datetime.now(timezone.utc)}},
        )
        log_security_event("drive_storage_enabled", user_id, "new uploads go to Google Drive")
    elif connection is not None:
        database.google_connections.update_one(
            {"user_id": user_id},
            {"$set": {"storage_enabled": False, "updated_at": datetime.now(timezone.utc)}},
        )
        log_security_event("drive_storage_disabled", user_id, "new uploads use default storage")

    return {"storage_enabled": body.enabled}