import hashlib
from datetime import datetime, timezone
import pytest
from agentproof.core.crypto import generate_keypair, sign_payload

async def _register_agent(client, private_key, public_key):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    return response.json()

@pytest.mark.asyncio
async def test_get_credential(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    response = await client.get(f"/agents/{did}/credential")
    assert response.status_code == 200
    result = response.json()
    assert "credential_jwt" in result
    assert result["credential_jwt"] == data["credential_jwt"]

@pytest.mark.asyncio
async def test_get_credential_unknown_did(client):
    response = await client.get("/agents/did:key:z6MkNonexistent/credential")
    assert response.status_code == 404
