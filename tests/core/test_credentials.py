import time

import jwt

from agentproof.core.credentials import issue_credential, verify_credential
from agentproof.core.crypto import generate_keypair
from agentproof.core.did import pubkey_to_did


def test_issue_l0_credential():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    assert isinstance(token, str)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == "did:web:agentproof.dev"
    assert claims["sub"] == agent_did
    assert claims["vc"]["credentialSubject"]["verificationLevel"] == 0
    assert claims["vc"]["credentialSubject"]["emailVerified"] is False
    assert "exp" in claims
    assert "iat" in claims


def test_issue_l1_credential():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=1,
        email_verified=True,
        ttl_days=90,
    )

    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["vc"]["credentialSubject"]["verificationLevel"] == 1
    assert claims["vc"]["credentialSubject"]["emailVerified"] is True


def test_verify_credential_valid():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    claims = verify_credential(token, issuer_public)
    assert claims is not None
    assert claims["sub"] == agent_did


def test_verify_credential_wrong_key():
    issuer_private, _ = generate_keypair()
    _, wrong_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    claims = verify_credential(token, wrong_public)
    assert claims is None


def test_verify_credential_expired():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=-1,
    )

    claims = verify_credential(token, issuer_public)
    assert claims is None
