from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from agentproof.db.models import Agent
from agentproof.db.session import get_session

router = APIRouter()

class CredentialResponse(BaseModel):
    did: str
    credential_jwt: str

@router.get("/agents/{did:path}/credential", response_model=CredentialResponse)
async def get_credential(did: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.revoked:
        raise HTTPException(status_code=410, detail="Agent credential has been revoked")
    if agent.credential_jwt is None:
        raise HTTPException(status_code=404, detail="No credential issued")
    return CredentialResponse(did=agent.did, credential_jwt=agent.credential_jwt)
