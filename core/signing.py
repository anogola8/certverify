"""
Ed25519 signing for CertVerify.

Each Institution owns a keypair. The private key signs certificate hashes;
the public key is published so anyone can verify — independent of the
CertVerify server.

Storage note: for MVP, private keys live in the DB (base64-encoded raw
bytes). In production, the private key should live in an HSM or an
encrypted vault on the institution's own infrastructure.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# --------------------------------------------------------------------------- #
#  Key generation
# --------------------------------------------------------------------------- #

def generate_keypair() -> tuple[str, str]:
    """
    Return (private_key_b64, public_key_b64).
    Both are URL-safe base64 strings.
    """
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.urlsafe_b64encode(priv_bytes).decode(),
        base64.urlsafe_b64encode(pub_bytes).decode(),
    )


# --------------------------------------------------------------------------- #
#  Signing
# --------------------------------------------------------------------------- #

def sign_hash(private_key_b64: str, cert_hash: str) -> str:
    """
    Sign the hex-encoded certificate hash. Returns URL-safe base64 signature.
    """
    priv_bytes = base64.urlsafe_b64decode(private_key_b64.encode())
    private = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # Hash the cert_hash again to a fixed length — we're signing "this hash"
    message = cert_hash.encode("utf-8")
    signature = private.sign(message)

    return base64.urlsafe_b64encode(signature).decode()


# --------------------------------------------------------------------------- #
#  Verification
# --------------------------------------------------------------------------- #

def verify_signature(public_key_b64: str, cert_hash: str, signature_b64: str) -> bool:
    """
    Return True iff `signature_b64` is a valid signature of `cert_hash`
    under `public_key_b64`.
    """
    try:
        pub_bytes = base64.urlsafe_b64decode(public_key_b64.encode())
        public = Ed25519PublicKey.from_public_bytes(pub_bytes)

        sig_bytes = base64.urlsafe_b64decode(signature_b64.encode())
        message = cert_hash.encode("utf-8")

        public.verify(sig_bytes, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
#  Payload hashing helper (for receipts, audit log, etc.)
# --------------------------------------------------------------------------- #

def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()