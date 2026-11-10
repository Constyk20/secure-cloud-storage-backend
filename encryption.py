import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    return os.urandom(12)


def encrypt_file(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def generate_rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def wrap_aes_key(aes_key: bytes, public_key) -> bytes:
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_aes_key(wrapped_key: bytes, private_key) -> bytes:
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )