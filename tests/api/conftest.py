import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentdid.api.app import create_app
from agentdid.core.crypto import generate_keypair
from agentdid.db.models import Base
from agentdid.db.session import get_session


@pytest.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
def issuer_keypair():
    return generate_keypair()


@pytest.fixture
def app(db_engine, issuer_keypair):
    test_app = create_app()
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_session():
        async with session_factory() as session:
            yield session

    test_app.dependency_overrides[get_session] = override_get_session
    test_app.state.issuer_private_key = issuer_keypair[0]
    test_app.state.issuer_public_key = issuer_keypair[1]
    return test_app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test/v1") as ac:
        yield ac
