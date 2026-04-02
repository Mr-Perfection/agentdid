import base58
from fastapi import APIRouter, Request
from agentproof.core.config import settings

router = APIRouter()
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"

@router.get("/.well-known/did.json")
async def did_document(request: Request):
    issuer_public_key = request.app.state.issuer_public_key
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + issuer_public_key
    public_key_multibase = "z" + base58.b58encode(multicodec_bytes).decode("ascii")
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": settings.issuer_did,
        "verificationMethod": [{
            "id": f"{settings.issuer_did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": settings.issuer_did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "authentication": [f"{settings.issuer_did}#key-1"],
        "assertionMethod": [f"{settings.issuer_did}#key-1"],
    }
