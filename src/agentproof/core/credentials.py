import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def issue_credential(
    issuer_private_key: bytes,
    issuer_did: str,
    agent_did: str,
    verification_level: int,
    email_verified: bool,
    ttl_days: int,
) -> str:
    now = int(time.time())
    exp = now + (ttl_days * 86400)

    payload = {
        "iss": issuer_did,
        "sub": agent_did,
        "iat": now,
        "exp": exp,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "AgentOwnershipCredential"],
            "credentialSubject": {
                "id": agent_did,
                "verificationLevel": verification_level,
                "emailVerified": email_verified,
            },
        },
    }

    # PyJWT's EdDSA (OKPAlgorithm) requires cryptography Ed25519 key objects.
    # Our keypairs are stored as raw 32-byte seeds (private) and public key bytes.
    priv_key = Ed25519PrivateKey.from_private_bytes(issuer_private_key)
    return jwt.encode(payload, priv_key, algorithm="EdDSA")


def verify_credential(token: str, issuer_public_key: bytes) -> dict | None:
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(issuer_public_key)
        claims = jwt.decode(token, pub_key, algorithms=["EdDSA"])
        return claims
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError, Exception):
        return None
