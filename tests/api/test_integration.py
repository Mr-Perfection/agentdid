import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from agentproof.core.crypto import generate_keypair, sign_payload

def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature

@pytest.mark.asyncio
async def test_full_l0_to_l1_flow(client):
    private_key, public_key = generate_keypair()

    # 1. Register (L0)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    reg_resp = await client.post("/agents/register", json={
        "public_key": public_key.hex(), "timestamp": timestamp,
        "signature": signature.hex(), "display_name": "integration-test-agent",
        "owner_email": "test@example.com",
    })
    assert reg_resp.status_code == 200
    did = reg_resp.json()["did"]
    assert reg_resp.json()["verification_level"] == 0

    # 2. Public verify — L0
    verify_resp = await client.get(f"/agents/{did}/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verification_level"] == 0
    assert verify_resp.json()["valid"] is True

    # 3. Get credential
    cred_resp = await client.get(f"/agents/{did}/credential")
    assert cred_resp.status_code == 200
    assert cred_resp.json()["credential_jwt"] == reg_resp.json()["credential_jwt"]

    # 4. Trigger email verification
    ts1, sig1 = _sign_mutation(private_key, did, "verify-email")
    captured_code = {}
    async def fake_send(email, code):
        captured_code["code"] = code
        return True
    with patch("agentproof.api.routes.email.send_verification_email", side_effect=fake_send):
        email_resp = await client.post(f"/agents/{did}/verify-email", json={
            "timestamp": ts1, "signature": sig1.hex(),
        })
    assert email_resp.status_code == 200

    # 5. Confirm email — upgrade to L1
    ts2, sig2 = _sign_mutation(private_key, did, "confirm-email")
    confirm_resp = await client.post(f"/agents/{did}/confirm-email", json={
        "code": captured_code["code"], "timestamp": ts2, "signature": sig2.hex(),
    })
    assert confirm_resp.status_code == 200
    assert confirm_resp.json()["verification_level"] == 1

    # 6. Verify — L1
    verify_resp2 = await client.get(f"/agents/{did}/verify")
    assert verify_resp2.json()["verification_level"] == 1
    assert verify_resp2.json()["email_verified"] is True

    # 7. Revoke
    ts3, sig3 = _sign_mutation(private_key, did, "revoke")
    revoke_resp = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": ts3, "signature": sig3.hex(),
    })
    assert revoke_resp.status_code == 200

    # 8. Verify — revoked
    verify_resp3 = await client.get(f"/agents/{did}/verify")
    assert verify_resp3.json()["revoked"] is True
    assert verify_resp3.json()["valid"] is False
