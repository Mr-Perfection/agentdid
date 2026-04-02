from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair. Returns (private_key_seed, public_key) as raw bytes."""
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def sign_payload(private_key: bytes, payload: bytes) -> bytes:
    """Sign a payload with an Ed25519 private key. Returns the 64-byte signature."""
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(payload)
    return signed.signature


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    verify_key = VerifyKey(public_key)
    try:
        verify_key.verify(payload, signature)
        return True
    except BadSignatureError:
        return False
