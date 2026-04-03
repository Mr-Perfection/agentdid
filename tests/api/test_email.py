import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from agentdid.core.crypto import generate_keypair, sign_payload

async def _register_agent(client, private_key, public_key, email="test@example.com"):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "owner_email": email,
    })
    return response.json()

def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature

@pytest.mark.asyncio
async def test_verify_email_sends_code(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    timestamp, signature = _sign_mutation(private_key, did, "verify-email")
    with patch("agentdid.api.routes.email.send_verification_email", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        response = await client.post(f"/agents/{did}/verify-email", json={
            "timestamp": timestamp,
            "signature": signature.hex(),
        })
    assert response.status_code == 200
    assert response.json()["message"] == "Verification code sent"
    mock_send.assert_called_once()

@pytest.mark.asyncio
async def test_verify_email_no_email_on_file(client):
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    resp = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    did = resp.json()["did"]
    ts, sig = _sign_mutation(private_key, did, "verify-email")
    response = await client.post(f"/agents/{did}/verify-email", json={
        "timestamp": ts,
        "signature": sig.hex(),
    })
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_confirm_email_upgrades_to_l1(client, db_session):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    ts1, sig1 = _sign_mutation(private_key, did, "verify-email")
    captured_code = {}
    async def fake_send(email, code):
        captured_code["code"] = code
        return True
    with patch("agentdid.api.routes.email.send_verification_email", side_effect=fake_send):
        await client.post(f"/agents/{did}/verify-email", json={
            "timestamp": ts1,
            "signature": sig1.hex(),
        })
    ts2, sig2 = _sign_mutation(private_key, did, "confirm-email")
    response = await client.post(f"/agents/{did}/confirm-email", json={
        "code": captured_code["code"],
        "timestamp": ts2,
        "signature": sig2.hex(),
    })
    assert response.status_code == 200
    result = response.json()
    assert result["verification_level"] == 1
    assert "credential_jwt" in result

@pytest.mark.asyncio
async def test_confirm_email_wrong_code(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]
    ts1, sig1 = _sign_mutation(private_key, did, "verify-email")
    with patch("agentdid.api.routes.email.send_verification_email", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        await client.post(f"/agents/{did}/verify-email", json={
            "timestamp": ts1,
            "signature": sig1.hex(),
        })
    ts2, sig2 = _sign_mutation(private_key, did, "confirm-email")
    response = await client.post(f"/agents/{did}/confirm-email", json={
        "code": "000000",
        "timestamp": ts2,
        "signature": sig2.hex(),
    })
    assert response.status_code == 401
