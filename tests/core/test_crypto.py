import hashlib
from datetime import datetime, timezone

from agentproof.core.crypto import generate_keypair, sign_payload, verify_signature


def test_generate_keypair_returns_32_byte_keys():
    private_key, public_key = generate_keypair()
    assert len(private_key) == 32
    assert len(public_key) == 32


def test_generate_keypair_unique():
    pk1, _ = generate_keypair()
    pk2, _ = generate_keypair()
    assert pk1 != pk2


def test_sign_and_verify_registration_payload():
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(
        f"{public_key.hex()}:{timestamp}".encode()
    ).digest()
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature) is True


def test_verify_wrong_key_fails():
    private_key, _ = generate_keypair()
    _, other_public_key = generate_keypair()
    payload = b"test payload"
    signature = sign_payload(private_key, payload)
    assert verify_signature(other_public_key, payload, signature) is False


def test_verify_tampered_payload_fails():
    private_key, public_key = generate_keypair()
    payload = b"original"
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, b"tampered", signature) is False


def test_sign_mutation_payload():
    private_key, public_key = generate_keypair()
    did = "did:key:z6MkTest"
    action = "revoke"
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(
        f"{did}:{action}:{timestamp}".encode()
    ).digest()
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature) is True
