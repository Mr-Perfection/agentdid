import hashlib
from datetime import datetime, timezone
from unittest.mock import patch
import pytest
from agentproof.core.crypto import generate_keypair, sign_payload

async def _register_agent(client, private_key, public_key, display_name="test-agent"):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "display_name": display_name,
    })
    return response.json()

@pytest.mark.asyncio
async def test_verify_registered_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    response = await client.get(f"/agents/{did}/verify")
    assert response.status_code == 200
    result = response.json()
    assert result["did"] == did
    assert result["display_name"] == "test-agent"
    assert result["verification_level"] == 0
    assert result["email_verified"] is False
    assert result["valid"] is True
    assert result["revoked"] is False
    assert "created_at" in result
    assert "credential_expires" in result

@pytest.mark.asyncio
async def test_verify_unknown_did(client):
    response = await client.get("/agents/did:key:z6MkNonexistent/verify")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_verify_expired_credential(client):
    """verify returns valid=false when the credential JWT has expired."""
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    # Simulate a future time well past any reasonable credential TTL
    far_future = 9_999_999_999.0
    with patch("agentproof.api.routes.verify.time.time", return_value=far_future):
        response = await client.get(f"/agents/{did}/verify")
    assert response.status_code == 200
    result = response.json()
    assert result["valid"] is False
    assert result["revoked"] is False
