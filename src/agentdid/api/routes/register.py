import hashlib
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from agentdid.core.config import settings
from agentdid.core.credentials import issue_credential
from agentdid.core.crypto import verify_signature
from agentdid.core.did import pubkey_to_did
from agentdid.db.models import Agent
from agentdid.db.session import get_session
from agentdid.api.deps import verify_timestamp

router = APIRouter()

class RegisterRequest(BaseModel):
    public_key: str
    timestamp: str
    signature: str
    display_name: str | None = None
    owner_email: str | None = None

class RegisterResponse(BaseModel):
    did: str
    verification_level: int
    credential_jwt: str

@router.post("/agents/register", response_model=RegisterResponse)
async def register_agent(
    body: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        public_key = bytes.fromhex(body.public_key)
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding")
    if len(public_key) != 32:
        raise HTTPException(status_code=400, detail="Public key must be 32 bytes")
    if len(signature) != 64:
        raise HTTPException(status_code=400, detail="Signature must be 64 bytes")
    verify_timestamp(body.timestamp)
    payload = hashlib.sha256(f"{body.public_key}:{body.timestamp}".encode()).digest()
    if not verify_signature(public_key, payload, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    did = pubkey_to_did(public_key)
    existing = await session.execute(select(Agent).where(Agent.did == did))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Agent already registered")
    issuer_private_key = request.app.state.issuer_private_key
    credential_jwt = issue_credential(
        issuer_private_key=issuer_private_key,
        issuer_did=settings.issuer_did,
        agent_did=did,
        verification_level=0,
        email_verified=False,
        ttl_days=settings.credential_ttl_days,
    )
    agent = Agent(
        did=did,
        public_key=public_key,
        display_name=body.display_name,
        owner_email=body.owner_email,
        verification_level=0,
        credential_jwt=credential_jwt,
    )
    session.add(agent)
    await session.commit()
    return RegisterResponse(did=did, verification_level=0, credential_jwt=credential_jwt)
