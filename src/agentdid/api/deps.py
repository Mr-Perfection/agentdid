import hashlib
from datetime import datetime, timezone
from fastapi import HTTPException
from agentdid.core.config import settings
from agentdid.core.crypto import verify_signature

def verify_timestamp(timestamp: str) -> datetime:
    try:
        ts = datetime.fromisoformat(timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    diff = abs((now - ts).total_seconds())
    if diff > settings.timestamp_tolerance_seconds:
        raise HTTPException(status_code=401, detail="Timestamp expired")
    return ts

def verify_agent_signature(public_key: bytes, did: str, action: str, timestamp: str, signature: bytes) -> bool:
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    if not verify_signature(public_key, payload, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    return True
