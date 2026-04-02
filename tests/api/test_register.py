import hashlib
from datetime import datetime, timezone
import pytest
from agentproof.core.crypto import generate_keypair, sign_payload

@pytest.mark.asyncio
async def test_register_agent_success(client):
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "display_name": "test-agent",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["did"].startswith("did:key:z6Mk")
    assert data["verification_level"] == 0
    assert "credential_jwt" in data

@pytest.mark.asyncio
async def test_register_agent_bad_signature(client):
    _, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": ("aa" * 64),
        "display_name": "test-agent",
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_register_agent_expired_timestamp(client):
    private_key, public_key = generate_keypair()
    timestamp = "2020-01-01T00:00:00+00:00"
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_register_duplicate_agent(client):
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    body = {
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    }
    response1 = await client.post("/agents/register", json=body)
    assert response1.status_code == 200
    response2 = await client.post("/agents/register", json=body)
    assert response2.status_code == 409
