import hashlib
from datetime import datetime, timezone
import pytest
from agentdid.core.crypto import generate_keypair, sign_payload

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


@pytest.mark.asyncio
async def test_get_credential_revoked_agent_returns_410(client):
    """Credential endpoint returns 410 Gone for a revoked agent."""
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    # Revoke the agent
    timestamp = datetime.now(timezone.utc).isoformat()
    import hashlib
    payload = hashlib.sha256(f"{did}:revoke:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    revoke_resp = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["revoked"] is True
    # Now credential endpoint should return 410
    response = await client.get(f"/agents/{did}/credential")
    assert response.status_code == 410
    assert "revoked" in response.json()["detail"].lower()
