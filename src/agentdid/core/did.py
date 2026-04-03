import base58

_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def pubkey_to_did(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 public key, got {len(public_key)} bytes")
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + public_key
    encoded = base58.b58encode(multicodec_bytes).decode("ascii")
    return f"did:key:z{encoded}"


def did_to_pubkey(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: {did}")
    encoded = did[len("did:key:z"):]
    decoded = base58.b58decode(encoded)
    if not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError("DID does not contain an Ed25519 public key")
    return decoded[len(_ED25519_MULTICODEC_PREFIX):]
