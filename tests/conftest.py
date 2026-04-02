import pytest
from nacl.signing import SigningKey


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key


@pytest.fixture
def issuer_keypair():
    """Generate a fixed issuer keypair for testing."""
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key
