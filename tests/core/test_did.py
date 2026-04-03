from agentdid.core.crypto import generate_keypair
from agentdid.core.did import pubkey_to_did, did_to_pubkey


def test_pubkey_to_did_starts_with_did_key_z6Mk():
    _, public_key = generate_keypair()
    did = pubkey_to_did(public_key)
    assert did.startswith("did:key:z6Mk")


def test_pubkey_to_did_deterministic():
    _, public_key = generate_keypair()
    did1 = pubkey_to_did(public_key)
    did2 = pubkey_to_did(public_key)
    assert did1 == did2


def test_different_keys_different_dids():
    _, pk1 = generate_keypair()
    _, pk2 = generate_keypair()
    assert pubkey_to_did(pk1) != pubkey_to_did(pk2)


def test_did_to_pubkey_roundtrip():
    _, public_key = generate_keypair()
    did = pubkey_to_did(public_key)
    recovered = did_to_pubkey(did)
    assert recovered == public_key


def test_known_vector():
    pubkey = bytes(32)  # 32 zero bytes
    did = pubkey_to_did(pubkey)
    assert did.startswith("did:key:z")
    assert did_to_pubkey(did) == pubkey
