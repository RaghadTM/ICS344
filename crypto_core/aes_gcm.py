from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from dataclasses import dataclass

@dataclass
class AESGCMResult:
    key: bytes
    nonce: bytes
    ciphertext: bytes


def generate_aes_key_256() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_aes_gcm(plaintext: str, key: bytes | None = None) -> AESGCMResult:
    if key is None:
        key = generate_aes_key_256()

    aes = AESGCM(key)
    nonce = os.urandom(12)  # 12 bytes for GCM
    ciphertext = aes.encrypt(nonce, plaintext.encode(), associated_data=None)

    return AESGCMResult(key=key, nonce=nonce, ciphertext=ciphertext)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aes = AESGCM(key)
    plaintext_bytes = aes.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext_bytes.decode()


def encode_bundle(result: AESGCMResult) -> str:
    return (
        base64.b64encode(result.key).decode() + "::" +
        base64.b64encode(result.nonce).decode() + "::" +
        base64.b64encode(result.ciphertext).decode()
    )


def decode_bundle(bundle: str) -> AESGCMResult:
    key_b64, nonce_b64, ct_b64 = bundle.split("::")

    return AESGCMResult(
        key=base64.b64decode(key_b64),
        nonce=base64.b64decode(nonce_b64),
        ciphertext=base64.b64decode(ct_b64)
    )
