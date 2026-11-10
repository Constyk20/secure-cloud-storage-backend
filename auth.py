import base64
import os
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from bson import ObjectId
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError

from config import get_settings
from database import ensure_indexes, get_database

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()
password_hasher = PasswordHasher()
bearer_scheme = HTTPBearer(auto_error=False)


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _wrapping_key() -> bytes:
    # 32 bytes derived from the server secret. Not the user's password.
    raw = settings.HMAC_SECRET.encode("utf-8")
    if len(raw) < 16:
        raise RuntimeError("HMAC_SECRET is too short")
    return raw.ljust(32, b"0")[:32]


def _generate_wrapped_rsa_keys() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    nonce = os.urandom(12)
    ciphertext = AESGCM(_wrapping_key()).encrypt(nonce, private_pem, None)
    wrapped = base64.b64encode(nonce + ciphertext).decode("ascii")
    return public_pem.decode("utf-8"), wrapped


def unwrap_private_key(wrapped: str):
    blob = base64.b64decode(wrapped)
    nonce, ciphertext = blob[:12], blob[12:]
    private_pem = AESGCM(_wrapping_key()).decrypt(nonce, ciphertext, None)
    return serialization.load_pem_private_key(private_pem, password=None)


def _create_token(user_id: str, email: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "email": email, "role": role, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def public_user(document: dict) -> dict:
    return {
        "id": str(document["_id"]),
        "full_name": document["full_name"],
        "email": document["email"],
        "role": document["role"],
        "created_at": document["created_at"].isoformat(),
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id = payload.get("sub")
        if not user_id:
            raise JWTError()
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = get_database().users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest):
    ensure_indexes()
    email = body.email.lower()
    role = "admin" if settings.ADMIN_EMAIL and email == settings.ADMIN_EMAIL.lower() else "user"
    public_pem, wrapped_private = _generate_wrapped_rsa_keys()

    document = {
        "full_name": body.full_name.strip(),
        "email": email,
        "password_hash": password_hasher.hash(body.password),
        "role": role,
        "public_key_pem": public_pem,
        "wrapped_private_key": wrapped_private,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = get_database().users.insert_one(document)
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    document["_id"] = result.inserted_id
    return public_user(document)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = get_database().users.find_one({"email": body.email.lower()})
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    try:
        password_hasher.verify(user["password_hash"], body.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = _create_token(str(user["_id"]), user["email"], user["role"])
    return TokenResponse(access_token=token)


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return public_user(user)