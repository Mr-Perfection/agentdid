import pytest
from httpx import ASGITransport, AsyncClient

@pytest.mark.asyncio
async def test_well_known_did_json(app, issuer_keypair):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/did.json")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "did:web:rureal.ai"
    assert "verificationMethod" in data
    assert len(data["verificationMethod"]) == 1
    method = data["verificationMethod"][0]
    assert method["type"] == "Ed25519VerificationKey2020"
    assert "publicKeyMultibase" in method
