import hashlib
import secrets
from datetime import datetime, timedelta, timezone
import resend
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from agentproof.api.deps import verify_agent_signature, verify_timestamp
from agentproof.core.config import settings
from agentproof.core.credentials import issue_credential
from agentproof.db.models import Agent
from agentproof.db.session import get_session

router = APIRouter()

class VerifyEmailRequest(BaseModel):
    timestamp: str
    signature: str

class ConfirmEmailRequest(BaseModel):
    code: str
    timestamp: str
    signature: str

class ConfirmEmailResponse(BaseModel):
    verification_level: int
    credential_jwt: str

async def send_verification_email(email: str, code: str) -> bool:
    resend.api_key = settings.resend_api_key
    resend.Emails.send({
        "from": settings.resend_from_email,
        "to": [email],
        "subject": "AgentProof Email Verification",
        "text": f"Your verification code is: {code}\n\nThis code expires in 10 minutes.",
    })
    return True

@router.post("/agents/{did:path}/verify-email")
async def verify_email(did: str, body: VerifyEmailRequest, request: Request, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent.owner_email:
        raise HTTPException(status_code=400, detail="No email on file")
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "verify-email", body.timestamp, signature)
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    agent.email_verify_token = code_hash
    agent.email_verify_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    await session.commit()
    await send_verification_email(agent.owner_email, code)
    return {"message": "Verification code sent"}

@router.post("/agents/{did:path}/confirm-email", response_model=ConfirmEmailResponse)
async def confirm_email(did: str, body: ConfirmEmailRequest, request: Request, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "confirm-email", body.timestamp, signature)
    if not agent.email_verify_token or not agent.email_verify_expires:
        raise HTTPException(status_code=400, detail="No pending verification")
    expires = agent.email_verify_expires
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise HTTPException(status_code=401, detail="Verification code expired")
    code_hash = hashlib.sha256(body.code.encode()).hexdigest()
    if code_hash != agent.email_verify_token:
        raise HTTPException(status_code=401, detail="Invalid verification code")
    agent.email_verified = True
    agent.verification_level = 1
    agent.email_verify_token = None
    agent.email_verify_expires = None
    agent.last_verified_at = datetime.now(timezone.utc)
    issuer_private_key = request.app.state.issuer_private_key
    credential_jwt = issue_credential(
        issuer_private_key=issuer_private_key,
        issuer_did=settings.issuer_did,
        agent_did=did,
        verification_level=1,
        email_verified=True,
        ttl_days=settings.credential_ttl_days,
    )
    agent.credential_jwt = credential_jwt
    await session.commit()
    return ConfirmEmailResponse(verification_level=1, credential_jwt=credential_jwt)
