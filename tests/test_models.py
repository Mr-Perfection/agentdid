import uuid
from datetime import datetime, timezone
from agentproof.db.models import Agent

def test_agent_model_instantiation():
    agent = Agent(
        id=uuid.uuid4(),
        did="did:key:z6MkTest",
        public_key=bytes(32),
        display_name="test-agent",
        verification_level=0,
    )
    assert agent.did == "did:key:z6MkTest"
    assert agent.display_name == "test-agent"
    assert agent.verification_level == 0
    assert agent.revoked is False
    assert agent.email_verified is False
