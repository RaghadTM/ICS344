from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64


@dataclass
class SecureMessageBundle:
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes
    signature: bytes  


def generate_rsa_keypair():
    """Generate RSA-2048 private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def wrap_aes_key(aes_key: bytes, receiver_public_key) -> bytes:
    """Encrypt (wrap) AES key using receiver's RSA public key."""
    wrapped = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped


def unwrap_aes_key(wrapped_key: bytes, receiver_private_key) -> bytes:
    """Decrypt (unwrap) AES key using receiver's RSA private key."""
    aes_key = receiver_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


def encode_secure_bundle(
    wrapped_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
) -> str:
    """Encode wrapped key + nonce + ciphertext + signature into Base64 string."""
    wk = base64.b64encode(wrapped_key).decode()
    n = base64.b64encode(nonce).decode()
    ct = base64.b64encode(ciphertext).decode()
    sig = base64.b64encode(signature).decode()
    return f"{wk}::{n}::{ct}::{sig}"


def decode_secure_bundle(bundle: str) -> SecureMessageBundle:
    """Decode bundle string back into raw bytes."""
    wk_b64, n_b64, ct_b64, sig_b64 = bundle.split("::")

    wrapped_key = base64.b64decode(wk_b64)
    nonce = base64.b64decode(n_b64)
    ciphertext = base64.b64decode(ct_b64)
    signature = base64.b64decode(sig_b64)

    return SecureMessageBundle(
        wrapped_key=wrapped_key,
        nonce=nonce,
        ciphertext=ciphertext,
        signature=signature,
    )
