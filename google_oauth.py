"""Google Drive OAuth 2.0 connection.

Endpoints:
  POST /google/connect     (Bearer) -> {"authorization_url": "..."}
  GET  /google/callback    (browser redirect from Google; identity comes from `state`)
  GET  /google/status      (Bearer) -> connection status (?verify=true forces a token refresh)
  POST /google/disconnect  (Bearer) -> revokes at Google and deletes stored credentials

google_drive.py calls get_valid_access_token(user_id) to talk to the Drive API.
Tokens never leave the backend.
"""
import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pymongo.errors import DuplicateKeyError

from auth import get_current_user
from config import get_settings
from database import get_database

router = APIRouter(prefix="/google", tags=["google"])
settings = get_settings()

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", DRIVE_FILE_SCOPE]

STATE_TTL_MINUTES = 10
ACCESS_TOKEN_SKEW_SECONDS = 60
HTTP_TIMEOUT = httpx.Timeout(15.0)


# --------------------------------------------------------------------------- helpers

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    # PyMongo returns naive datetimes (UTC) unless the client is tz_aware.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def api_error(code: str, message: str, http_status: int = 409) -> HTTPException:
    # Deliberately never 401: the frontend treats 401 as "app session expired".
    return HTTPException(status_code=http_status, detail={"code": code, "message": message})


def log_security_event(event: str, user_id: str, details: str) -> None:
    # Never put tokens or codes in here.
    get_database().security_logs.insert_one(
        {"event": event, "user_id": user_id, "details": details, "created_at": _utcnow()}
    )


def _drive_file_count(user_id: str) -> int:
    return get_database().files.count_documents({"owner_id": user_id, "storage_provider": "google_drive"})


def _token_key() -> bytes:
    key = base64.b64decode(settings.GOOGLE_TOKEN_ENCRYPTION_KEY, validate=True)
    if len(key) != 32:
        raise ValueError("GOOGLE_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def _ensure_configured() -> None:
    if not (
        settings.GOOGLE_CLIENT_ID
        and settings.GOOGLE_CLIENT_SECRET
        and settings.GOOGLE_REDIRECT_URI
        and settings.GOOGLE_TOKEN_ENCRYPTION_KEY
    ):
        raise api_error("google_not_configured", "Google Drive integration is not configured on the server", 503)
    try:
        _token_key()
    except ValueError:
        raise api_error("google_not_configured", "GOOGLE_TOKEN_ENCRYPTION_KEY is invalid", 503)


def _aad(user_id: str, purpose: str) -> bytes:
    # Binds a ciphertext to one user and one field.
    return f"google:{user_id}:{purpose}".encode("utf-8")


def encrypt_secret(plaintext: str, user_id: str, purpose: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_token_key()).encrypt(nonce, plaintext.encode("utf-8"), _aad(user_id, purpose))
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(blob: str, user_id: str, purpose: str) -> str:
    raw = base64.b64decode(blob)
    nonce, ciphertext = raw[:12], raw[12:]
    return AESGCM(_token_key()).decrypt(nonce, ciphertext, _aad(user_id, purpose)).decode("utf-8")


def _hash_state(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 chars (spec allows 43-128)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _post_form(url: str, data: dict) -> httpx.Response:
    try:
        return httpx.post(url, data=data, timeout=HTTP_TIMEOUT)
    except httpx.HTTPError:
        raise api_error("google_unreachable", "Could not reach Google. Please try again shortly.", 503)


def _revoke_token(token: str) -> bool:
    """Best-effort revoke. 400 means Google already considers it invalid, which is fine."""
    try:
        response = httpx.post(REVOKE_URL, data={"token": token}, timeout=HTTP_TIMEOUT)
    except httpx.HTTPError:
        return False
    return response.status_code in (200, 400)


def _redirect(result: str, reason: str | None = None) -> RedirectResponse:
    params = {"google": result}
    if reason:
        params["reason"] = reason
    url = f"{settings.FRONTEND_URL.rstrip('/')}/?{urlencode(params)}"
    return RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})


def mark_reauth_required(user_id: str) -> None:
    get_database().google_connections.update_one(
        {"user_id": user_id},
        {
            "$set": {"status": "reauth_required", "updated_at": _utcnow()},
            "$unset": {"refresh_token_enc": "", "access_token_enc": "", "access_token_expires_at": ""},
        },
    )
    log_security_event("google_reauth_required", user_id, "authorization expired or revoked")


# ------------------------------------------------------------- token access (used by Drive)

def get_valid_access_token(user_id: str, force_refresh: bool = False) -> str:
    """Return a usable Google access token for this app user, refreshing if needed.

    Raises HTTPException with detail.code in:
      google_not_connected, google_reauth_required, google_unreachable,
      google_rate_limited, google_unavailable, google_error, google_not_configured
    """
    _ensure_configured()
    database = get_database()
    connection = database.google_connections.find_one({"user_id": user_id})
    if connection is None:
        raise api_error("google_not_connected", "Google Drive is not connected")
    if connection.get("status") != "connected" or not connection.get("refresh_token_enc"):
        raise api_error("google_reauth_required", "Google Drive authorization expired or was revoked. Please reconnect.")

    expires_at = connection.get("access_token_expires_at")
    if (
        not force_refresh
        and connection.get("access_token_enc")
        and expires_at
        and _as_utc(expires_at) - timedelta(seconds=ACCESS_TOKEN_SKEW_SECONDS) > _utcnow()
    ):
        try:
            return decrypt_secret(connection["access_token_enc"], user_id, "access_token")
        except (InvalidTag, ValueError):
            pass  # fall through and refresh

    try:
        refresh_token = decrypt_secret(connection["refresh_token_enc"], user_id, "refresh_token")
    except (InvalidTag, ValueError):
        mark_reauth_required(user_id)
        raise api_error("google_reauth_required", "Stored Google credentials could not be read. Please reconnect.")

    response = _post_form(
        TOKEN_URL,
        {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )

    if response.status_code != 200:
        error_code = ""
        try:
            error_code = str(response.json().get("error", ""))
        except ValueError:
            pass
        if error_code == "invalid_grant":
            mark_reauth_required(user_id)
            raise api_error("google_reauth_required", "Google Drive authorization expired or was revoked. Please reconnect.")
        if response.status_code == 429:
            raise api_error("google_rate_limited", "Google is rate limiting requests. Try again shortly.", 429)
        if response.status_code >= 500:
            raise api_error("google_unavailable", "Google is temporarily unavailable. Try again shortly.", 503)
        raise api_error("google_error", "Google rejected the token refresh request", 502)

    try:
        payload = response.json()
        access_token = payload["access_token"]
        expires_in = int(payload.get("expires_in", 3600))
    except (ValueError, KeyError):
        raise api_error("google_error", "Unexpected response from Google", 502)

    update = {
        "access_token_enc": encrypt_secret(access_token, user_id, "access_token"),
        "access_token_expires_at": _utcnow() + timedelta(seconds=expires_in),
        "updated_at": _utcnow(),
    }
    if payload.get("refresh_token"):  # Google rarely rotates; handle it if it does
        update["refresh_token_enc"] = encrypt_secret(payload["refresh_token"], user_id, "refresh_token")
    database.google_connections.update_one({"user_id": user_id}, {"$set": update})
    return access_token


# ------------------------------------------------------------------------------ routes

@router.post("/connect")
def connect(user: dict = Depends(get_current_user)):
    _ensure_configured()
    database = get_database()
    user_id = str(user["_id"])

    database.google_oauth_states.delete_many({"user_id": user_id})  # one pending flow per user

    state = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    now = _utcnow()
    database.google_oauth_states.insert_one(
        {
            "state_hash": _hash_state(state),
            "user_id": user_id,
            "code_verifier": verifier,
            "created_at": now,
            "expires_at": now + timedelta(minutes=STATE_TTL_MINUTES),
        }
    )

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    return {"authorization_url": f"{AUTH_URL}?{urlencode(params, quote_via=quote)}"}


@router.get("/callback")
def callback(code: str | None = None, state: str | None = None, error: str | None = None):
    _ensure_configured()
    database = get_database()

    # Validate and consume state first (atomic, single use), whatever else happens.
    record = None
    if state:
        record = database.google_oauth_states.find_one_and_delete({"state_hash": _hash_state(state)})
    if record is None or _as_utc(record["expires_at"]) <= _utcnow():
        return _redirect("error", "invalid_state")
    user_id = record["user_id"]

    if error or not code:
        reason = "access_denied" if error == "access_denied" else "oauth_error"
        log_security_event("google_oauth_failed", user_id, reason)
        return _redirect("error", reason)

    # Exchange the code (PKCE verifier proves this is the same browser flow).
    try:
        response = _post_form(
            TOKEN_URL,
            {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "code_verifier": record["code_verifier"],
                "grant_type": "authorization_code",
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            },
        )
        if response.status_code != 200:
            raise ValueError("token exchange rejected")
        tokens = response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens.get("refresh_token")
        expires_in = int(tokens.get("expires_in", 3600))
        granted = set(str(tokens.get("scope", "")).split())
    except (HTTPException, ValueError, KeyError):
        log_security_event("google_oauth_failed", user_id, "token_exchange_failed")
        return _redirect("error", "token_exchange_failed")

    # Users can untick permissions on the consent screen; require what we need.
    # (We do not revoke on these failure paths: that could invalidate an existing
    # working grant for the same Google account.)
    if DRIVE_FILE_SCOPE not in granted:
        log_security_event("google_oauth_failed", user_id, "drive_scope_missing")
        return _redirect("error", "drive_scope_missing")
    if not refresh_token:
        log_security_event("google_oauth_failed", user_id, "no_refresh_token")
        return _redirect("error", "no_refresh_token")

    # Identify the linked Google account.
    try:
        info = httpx.get(
            USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=HTTP_TIMEOUT,
        )
        info.raise_for_status()
        profile = info.json()
        google_sub = str(profile["sub"])
        google_email = str(profile.get("email", ""))
    except (httpx.HTTPError, ValueError, KeyError):
        log_security_event("google_oauth_failed", user_id, "userinfo_failed")
        return _redirect("error", "userinfo_failed")

    # One Google account may be linked to only one app user.
    if database.google_connections.find_one({"google_sub": google_sub, "user_id": {"$ne": user_id}}):
        log_security_event("google_oauth_failed", user_id, "account_in_use")
        return _redirect("error", "account_in_use")

    previous = database.google_connections.find_one({"user_id": user_id})
    switching_account = bool(
        previous and previous.get("google_sub") and previous["google_sub"] != google_sub
    )

    # Files already stored in the old Drive would become unreachable.
    if switching_account and database.files.count_documents(
        {"owner_id": user_id, "storage_provider": "google_drive"}, limit=1
    ):
        log_security_event("google_oauth_failed", user_id, "account_has_drive_files")
        return _redirect("error", "account_has_drive_files")

    now = _utcnow()
    update = {
        "$set": {
            "google_sub": google_sub,
            "google_email": google_email,
            "scopes": sorted(granted),
            "refresh_token_enc": encrypt_secret(refresh_token, user_id, "refresh_token"),
            "access_token_enc": encrypt_secret(access_token, user_id, "access_token"),
            "access_token_expires_at": now + timedelta(seconds=expires_in),
            "status": "connected",
            "connected_at": now,
            "updated_at": now,
        }
    }
    if switching_account:
        update["$set"]["storage_enabled"] = False
        update["$unset"] = {"drive_folder_id": ""}

    try:
        database.google_connections.update_one({"user_id": user_id}, update, upsert=True)
    except DuplicateKeyError:
        log_security_event("google_oauth_failed", user_id, "account_in_use")
        return _redirect("error", "account_in_use")

    # Switched to a different Google account: revoke the old grant (best effort).
    # Same account: do NOT revoke, it could invalidate the grant we just created.
    if switching_account and previous.get("refresh_token_enc"):
        try:
            _revoke_token(decrypt_secret(previous["refresh_token_enc"], user_id, "refresh_token"))
        except (InvalidTag, ValueError):
            pass

    log_security_event("google_connected", user_id, google_email)
    return _redirect("connected")


@router.get("/status")
def google_status(verify: bool = False, user: dict = Depends(get_current_user)):
    user_id = str(user["_id"])
    configured = bool(
        settings.GOOGLE_CLIENT_ID
        and settings.GOOGLE_CLIENT_SECRET
        and settings.GOOGLE_REDIRECT_URI
        and settings.GOOGLE_TOKEN_ENCRYPTION_KEY
    )
    database = get_database()
    connection = database.google_connections.find_one({"user_id": user_id})
    verify_error = None

    if connection is not None and verify and connection.get("status") == "connected":
        try:
            get_valid_access_token(user_id, force_refresh=True)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            verify_error = detail.get("code", "google_error")
        connection = database.google_connections.find_one({"user_id": user_id})

    drive_file_count = _drive_file_count(user_id)

    if connection is None:
        return {
            "configured": configured,
            "connected": False,
            "status": "not_connected",
            "storage_enabled": False,
            "drive_file_count": drive_file_count,
        }

    connection_status = connection.get("status", "connected")
    result = {
        "configured": configured,
        "connected": connection_status == "connected",
        "status": connection_status,  # connected | reauth_required
        "google_email": connection.get("google_email"),
        "connected_at": _as_utc(connection["connected_at"]).isoformat() if connection.get("connected_at") else None,
        "scope": "drive.file",
        "storage_enabled": bool(connection.get("storage_enabled", False)),
        "drive_file_count": drive_file_count,
    }
    if verify_error:
        result["verify_error"] = verify_error
    return result


@router.post("/disconnect")
def disconnect(user: dict = Depends(get_current_user)):
    user_id = str(user["_id"])
    database = get_database()
    drive_file_count = _drive_file_count(user_id)
    connection = database.google_connections.find_one({"user_id": user_id})
    if connection is None:
        return {"disconnected": True, "revoked_at_google": False, "drive_file_count": drive_file_count}

    revoked = False
    if connection.get("refresh_token_enc"):
        try:
            revoked = _revoke_token(decrypt_secret(connection["refresh_token_enc"], user_id, "refresh_token"))
        except (InvalidTag, ValueError):
            revoked = False

    # Always remove local credentials (this also turns Drive storage off for new uploads),
    # even if Google could not be reached.
    database.google_connections.delete_one({"user_id": user_id})
    database.google_oauth_states.delete_many({"user_id": user_id})
    log_security_event("google_disconnected", user_id, "revoked" if revoked else "revoke_failed_credentials_deleted")
    return {"disconnected": True, "revoked_at_google": revoked, "drive_file_count": drive_file_count}