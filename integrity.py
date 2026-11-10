import hashlib
import hmac

from config import get_settings


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _secret() -> bytes:
    secret = get_settings().HMAC_SECRET.encode("utf-8")
    if len(secret) < 16:
        raise RuntimeError("HMAC_SECRET is too short")
    return secret


def metadata_hmac(
    owner_id: str,
    storage_path: str,
    original_sha256: str,
    nonce_b64: str,
    wrapped_key_b64: str,
) -> str:
    message = "|".join(
        [owner_id, storage_path, original_sha256, nonce_b64, wrapped_key_b64]
    ).encode("utf-8")
    return hmac.new(_secret(), message, hashlib.sha256).hexdigest()


def verify_metadata_hmac(
    owner_id: str,
    storage_path: str,
    original_sha256: str,
    nonce_b64: str,
    wrapped_key_b64: str,
    expected_hmac: str,
) -> bool:
    actual = metadata_hmac(
        owner_id, storage_path, original_sha256, nonce_b64, wrapped_key_b64
    )
    return hmac.compare_digest(actual, expected_hmac)


def verify_plaintext(plaintext: bytes, expected_sha256: str) -> bool:
    return hmac.compare_digest(sha256_digest(plaintext), expected_sha256)