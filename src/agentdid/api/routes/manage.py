from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from agentdid.api.deps import verify_agent_signature, verify_timestamp
from agentdid.db.models import Agent
from agentdid.db.session import get_session

router = APIRouter()

class SignedRequest(BaseModel):
    timestamp: str
    signature: str

@router.post("/agents/{did:path}/revoke")
async def revoke_agent(did: str, body: SignedRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "revoke", body.timestamp, signature)
    agent.revoked = True
    await session.commit()
    return {"did": did, "revoked": True}

@router.delete("/agents/{did:path}")
async def delete_agent(did: str, body: SignedRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "delete", body.timestamp, signature)
    await session.delete(agent)
    await session.commit()
    return {"did": did, "deleted": True}
