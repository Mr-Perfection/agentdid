import hashlib
import json
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

def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature

@pytest.mark.asyncio
async def test_revoke_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    timestamp, signature = _sign_mutation(private_key, did, "revoke")
    response = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    assert response.status_code == 200
    assert response.json()["revoked"] is True
    verify_resp = await client.get(f"/agents/{did}/verify")
    assert verify_resp.json()["revoked"] is True
    assert verify_resp.json()["valid"] is False

@pytest.mark.asyncio
async def test_revoke_wrong_signature(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    other_private, _ = generate_keypair()
    timestamp, signature = _sign_mutation(other_private, did, "revoke")
    response = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_delete_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    timestamp, signature = _sign_mutation(private_key, did, "delete")
    body = json.dumps({"timestamp": timestamp, "signature": signature.hex()})
    response = await client.request(
        "DELETE",
        f"/agents/{did}",
        content=body.encode(),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200
    verify_resp = await client.get(f"/agents/{did}/verify")
    assert verify_resp.status_code == 404
