import json
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def canonicalize(obj: Any) -> bytes:
    """
    Before signing or verifying anything, serialize the object as JSON with keys
    sorted alphabetically, no whitespace, UTF-8 encoded.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def generate_keypair() -> tuple[str, str]:
    """
    Generates an Ed25519 keypair.
    Returns (public_key_hex, private_key_hex).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pub_bytes.hex(), priv_bytes.hex()


def sign_payload(private_key_hex: str, payload: Any) -> str:
    """
    Canonicalizes the payload and signs it using the Ed25519 private key.
    Returns the signature in hex.
    """
    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    canonical_data = canonicalize(payload)
    signature = private_key.sign(canonical_data)
    return signature.hex()


def verify_payload_signature(public_key_hex: str, signature_hex: str, payload: Any) -> bool:
    """
    Canonicalizes the payload and verifies the Ed25519 signature against the public key.
    Returns True if signature is valid, False otherwise.
    """
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        canonical_data = canonicalize(payload)
        public_key.verify(sig_bytes, canonical_data)
        return True
    except Exception:
        return False
