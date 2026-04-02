import time
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from agentproof.db.models import Agent
from agentproof.db.session import get_session

router = APIRouter()

class VerifyResponse(BaseModel):
    did: str
    display_name: str | None
    verification_level: int
    email_verified: bool
    valid: bool
    revoked: bool
    created_at: str
    credential_expires: str | None

@router.get("/agents/{did:path}/verify", response_model=VerifyResponse)
async def verify_agent(did: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    credential_expires = None
    credential_expired = False
    if agent.credential_jwt:
        try:
            claims = pyjwt.decode(agent.credential_jwt, options={"verify_signature": False})
            exp = claims.get("exp")
            if exp:
                from datetime import datetime, timezone
                credential_expires = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
                credential_expired = exp < time.time()
        except pyjwt.InvalidTokenError:
            credential_expired = True
    valid = not agent.revoked and agent.credential_jwt is not None and not credential_expired
    return VerifyResponse(
        did=agent.did,
        display_name=agent.display_name,
        verification_level=agent.verification_level,
        email_verified=agent.email_verified,
        valid=valid,
        revoked=agent.revoked,
        created_at=agent.created_at.isoformat(),
        credential_expires=credential_expires,
    )
