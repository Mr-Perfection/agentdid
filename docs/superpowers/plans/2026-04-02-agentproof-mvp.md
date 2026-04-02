# AgentProof MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an API + CLI that lets anyone register an AI agent's Ed25519 public key and get a signed JWT credential proving "a human controls this agent."

**Architecture:** FastAPI REST API backed by PostgreSQL (async via asyncpg). Python CLI (Click) talks to the API over HTTP. Shared `core/` module handles Ed25519 crypto, DID derivation, and JWT credential issuance. Deployed to Fly.io.

**Tech Stack:** FastAPI, SQLAlchemy (async), Alembic, PyNaCl, PyJWT, Click, Resend, asyncpg, httpx

---

## File Structure

```
agentproof/
├── src/agentproof/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── crypto.py          # Ed25519 keypair gen, signing, verification
│   │   ├── did.py             # did:key derivation from Ed25519 pubkey
│   │   ├── credentials.py     # JWT credential issuance and verification
│   │   └── config.py          # Pydantic settings (DB URL, issuer key, etc.)
│   ├── db/
│   │   ├── __init__.py
│   │   ├── models.py          # SQLAlchemy Agent model
│   │   └── session.py         # Async engine + session factory
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py             # FastAPI app factory + lifespan
│   │   ├── deps.py            # Dependency injection (DB session, signature verify)
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── register.py    # POST /agents/register
│   │       ├── verify.py      # GET /agents/{did}/verify
│   │       ├── credential.py  # GET /agents/{did}/credential
│   │       ├── email.py       # POST verify-email + confirm-email
│   │       ├── manage.py      # POST revoke + DELETE agent
│   │       └── well_known.py  # GET /.well-known/did.json
│   └── cli/
│       ├── __init__.py
│       ├── main.py            # Click group + shared options
│       ├── keygen.py          # keygen command
│       ├── register.py        # register command
│       ├── verify.py          # verify command
│       ├── email.py           # verify-email + confirm-email commands
│       ├── revoke.py          # revoke command
│       └── credential.py      # credential export command
├── tests/
│   ├── conftest.py            # Shared fixtures (test DB, keypairs)
│   ├── core/
│   │   ├── test_crypto.py
│   │   ├── test_did.py
│   │   └── test_credentials.py
│   ├── api/
│   │   ├── conftest.py        # FastAPI test client fixture
│   │   ├── test_register.py
│   │   ├── test_verify.py
│   │   ├── test_credential.py
│   │   ├── test_email.py
│   │   └── test_manage.py
│   └── cli/
│       ├── conftest.py        # CLI runner fixture
│       ├── test_keygen.py
│       ├── test_register.py
│       ├── test_verify.py
│       └── test_email.py
├── alembic/
│   ├── env.py
│   └── versions/
├── alembic.ini
├── pyproject.toml
├── Dockerfile
└── fly.toml
```

---

## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/agentproof/__init__.py`
- Create: `src/agentproof/core/__init__.py`
- Create: `src/agentproof/core/config.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "agentproof"
version = "0.1.0"
description = "Cryptographic proof that a human stands behind an AI agent."
readme = "README.md"
requires-python = ">=3.11"
license = "MIT"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "asyncpg>=0.30.0",
    "alembic>=1.13.0",
    "pynacl>=1.5.0",
    "pyjwt>=2.9.0",
    "click>=8.1.0",
    "httpx>=0.27.0",
    "resend>=2.0.0",
    "pydantic-settings>=2.0.0",
    "base58>=2.1.0",
    "tomli>=2.0.0;python_version<'3.11'",
    "tomli-w>=1.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=5.0.0",
    "aiosqlite>=0.20.0",
]

[project.scripts]
agentproof = "agentproof.cli.main:cli"

[tool.hatch.build.targets.wheel]
packages = ["src/agentproof"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create package init files**

`src/agentproof/__init__.py`:
```python
"""AgentProof: Cryptographic proof that a human stands behind an AI agent."""

__version__ = "0.1.0"
```

`src/agentproof/core/__init__.py`:
```python
```

- [ ] **Step 3: Create config module**

`src/agentproof/core/config.py`:
```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://localhost:5432/agentproof"
    issuer_private_key_hex: str = ""
    issuer_did: str = "did:web:agentproof.dev"
    credential_ttl_days: int = 90
    timestamp_tolerance_seconds: int = 300
    resend_api_key: str = ""
    resend_from_email: str = "verify@agentproof.dev"
    api_base_url: str = "https://api.agentproof.dev/v1"

    model_config = {"env_prefix": "AGENTPROOF_"}


settings = Settings()
```

- [ ] **Step 4: Create test conftest with shared fixtures**

`tests/conftest.py`:
```python
import pytest
from nacl.signing import SigningKey


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key


@pytest.fixture
def issuer_keypair():
    """Generate a fixed issuer keypair for testing."""
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key
```

- [ ] **Step 5: Install and verify**

Run:
```bash
pip install -e ".[dev]"
python -c "import agentproof; print(agentproof.__version__)"
```
Expected: `0.1.0`

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/ tests/conftest.py
git commit -m "feat: project scaffolding with pyproject.toml and config"
```

---

## Task 2: Core Crypto — Ed25519 Key Handling

**Files:**
- Create: `src/agentproof/core/crypto.py`
- Create: `tests/core/__init__.py`
- Create: `tests/core/test_crypto.py`

- [ ] **Step 1: Write failing tests for keypair generation and signing**

`tests/core/__init__.py`:
```python
```

`tests/core/test_crypto.py`:
```python
import hashlib
from datetime import datetime, timezone

from agentproof.core.crypto import generate_keypair, sign_payload, verify_signature


def test_generate_keypair_returns_32_byte_keys():
    private_key, public_key = generate_keypair()
    assert len(private_key) == 32
    assert len(public_key) == 32


def test_generate_keypair_unique():
    pk1, _ = generate_keypair()
    pk2, _ = generate_keypair()
    assert pk1 != pk2


def test_sign_and_verify_registration_payload():
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(
        f"{public_key.hex()}:{timestamp}".encode()
    ).digest()
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature) is True


def test_verify_wrong_key_fails():
    private_key, _ = generate_keypair()
    _, other_public_key = generate_keypair()
    payload = b"test payload"
    signature = sign_payload(private_key, payload)
    assert verify_signature(other_public_key, payload, signature) is False


def test_verify_tampered_payload_fails():
    private_key, public_key = generate_keypair()
    payload = b"original"
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, b"tampered", signature) is False


def test_sign_mutation_payload():
    private_key, public_key = generate_keypair()
    did = "did:key:z6MkTest"
    action = "revoke"
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(
        f"{did}:{action}:{timestamp}".encode()
    ).digest()
    signature = sign_payload(private_key, payload)
    assert verify_signature(public_key, payload, signature) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/core/test_crypto.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentproof.core.crypto'`

- [ ] **Step 3: Implement crypto module**

`src/agentproof/core/crypto.py`:
```python
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair. Returns (private_key_seed, public_key) as raw bytes."""
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def sign_payload(private_key: bytes, payload: bytes) -> bytes:
    """Sign a payload with an Ed25519 private key. Returns the 64-byte signature."""
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(payload)
    return signed.signature


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    verify_key = VerifyKey(public_key)
    try:
        verify_key.verify(payload, signature)
        return True
    except BadSignatureError:
        return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/core/test_crypto.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/core/crypto.py tests/core/
git commit -m "feat: Ed25519 keypair generation, signing, and verification"
```

---

## Task 3: Core Crypto — DID Derivation

**Files:**
- Create: `src/agentproof/core/did.py`
- Create: `tests/core/test_did.py`

- [ ] **Step 1: Write failing tests for DID derivation**

`tests/core/test_did.py`:
```python
from agentproof.core.crypto import generate_keypair
from agentproof.core.did import pubkey_to_did, did_to_pubkey


def test_pubkey_to_did_starts_with_did_key_z6Mk():
    _, public_key = generate_keypair()
    did = pubkey_to_did(public_key)
    assert did.startswith("did:key:z6Mk")


def test_pubkey_to_did_deterministic():
    _, public_key = generate_keypair()
    did1 = pubkey_to_did(public_key)
    did2 = pubkey_to_did(public_key)
    assert did1 == did2


def test_different_keys_different_dids():
    _, pk1 = generate_keypair()
    _, pk2 = generate_keypair()
    assert pubkey_to_did(pk1) != pubkey_to_did(pk2)


def test_did_to_pubkey_roundtrip():
    _, public_key = generate_keypair()
    did = pubkey_to_did(public_key)
    recovered = did_to_pubkey(did)
    assert recovered == public_key


def test_known_vector():
    """Test against a known did:key vector.
    Multicodec ed25519-pub prefix is 0xed01.
    The did:key is 'z' + base58btc(0xed01 + 32-byte-pubkey).
    """
    pubkey = bytes(32)  # 32 zero bytes
    did = pubkey_to_did(pubkey)
    # Verify the structure: must start with did:key:z
    assert did.startswith("did:key:z")
    # Roundtrip must recover the same key
    assert did_to_pubkey(did) == pubkey
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/core/test_did.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentproof.core.did'`

- [ ] **Step 3: Implement DID module**

`src/agentproof/core/did.py`:
```python
import base58

# Multicodec prefix for Ed25519 public key
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def pubkey_to_did(public_key: bytes) -> str:
    """Derive a did:key from a 32-byte Ed25519 public key.

    Format: did:key:z{base58btc(0xed01 + pubkey)}
    """
    if len(public_key) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 public key, got {len(public_key)} bytes")
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + public_key
    encoded = base58.b58encode(multicodec_bytes).decode("ascii")
    return f"did:key:z{encoded}"


def did_to_pubkey(did: str) -> bytes:
    """Extract the 32-byte Ed25519 public key from a did:key."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: {did}")
    encoded = did[len("did:key:z"):]
    decoded = base58.b58decode(encoded)
    if not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError("DID does not contain an Ed25519 public key")
    return decoded[len(_ED25519_MULTICODEC_PREFIX):]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/core/test_did.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/core/did.py tests/core/test_did.py
git commit -m "feat: did:key derivation from Ed25519 public key"
```

---

## Task 4: Core Crypto — JWT Credential Issuance

**Files:**
- Create: `src/agentproof/core/credentials.py`
- Create: `tests/core/test_credentials.py`

- [ ] **Step 1: Write failing tests for credential issuance and verification**

`tests/core/test_credentials.py`:
```python
import time

import jwt

from agentproof.core.credentials import issue_credential, verify_credential
from agentproof.core.crypto import generate_keypair
from agentproof.core.did import pubkey_to_did


def test_issue_l0_credential():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    assert isinstance(token, str)
    # Decode without verification to inspect claims
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == "did:web:agentproof.dev"
    assert claims["sub"] == agent_did
    assert claims["vc"]["credentialSubject"]["verificationLevel"] == 0
    assert claims["vc"]["credentialSubject"]["emailVerified"] is False
    assert "exp" in claims
    assert "iat" in claims


def test_issue_l1_credential():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=1,
        email_verified=True,
        ttl_days=90,
    )

    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["vc"]["credentialSubject"]["verificationLevel"] == 1
    assert claims["vc"]["credentialSubject"]["emailVerified"] is True


def test_verify_credential_valid():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    claims = verify_credential(token, issuer_public)
    assert claims is not None
    assert claims["sub"] == agent_did


def test_verify_credential_wrong_key():
    issuer_private, _ = generate_keypair()
    _, wrong_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=90,
    )

    claims = verify_credential(token, wrong_public)
    assert claims is None


def test_verify_credential_expired():
    issuer_private, issuer_public = generate_keypair()
    _, agent_public = generate_keypair()
    agent_did = pubkey_to_did(agent_public)

    token = issue_credential(
        issuer_private_key=issuer_private,
        issuer_did="did:web:agentproof.dev",
        agent_did=agent_did,
        verification_level=0,
        email_verified=False,
        ttl_days=-1,  # Already expired
    )

    claims = verify_credential(token, issuer_public)
    assert claims is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/core/test_credentials.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentproof.core.credentials'`

- [ ] **Step 3: Implement credentials module**

`src/agentproof/core/credentials.py`:
```python
import time

import jwt
from nacl.signing import SigningKey


def issue_credential(
    issuer_private_key: bytes,
    issuer_did: str,
    agent_did: str,
    verification_level: int,
    email_verified: bool,
    ttl_days: int,
) -> str:
    """Issue a Verifiable Credential as a JWT signed with the issuer's Ed25519 key."""
    now = int(time.time())
    exp = now + (ttl_days * 86400)

    payload = {
        "iss": issuer_did,
        "sub": agent_did,
        "iat": now,
        "exp": exp,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "AgentOwnershipCredential"],
            "credentialSubject": {
                "id": agent_did,
                "verificationLevel": verification_level,
                "emailVerified": email_verified,
            },
        },
    }

    signing_key = SigningKey(issuer_private_key)
    # PyJWT expects the full 64-byte key (seed + public) for EdDSA
    full_key = bytes(signing_key) + bytes(signing_key.verify_key)
    return jwt.encode(payload, full_key, algorithm="EdDSA")


def verify_credential(token: str, issuer_public_key: bytes) -> dict | None:
    """Verify a credential JWT. Returns claims if valid, None if invalid or expired."""
    try:
        claims = jwt.decode(
            token,
            issuer_public_key,
            algorithms=["EdDSA"],
        )
        return claims
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/core/test_credentials.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/core/credentials.py tests/core/test_credentials.py
git commit -m "feat: JWT credential issuance and verification"
```

---

## Task 5: Database Model and Migrations

**Files:**
- Create: `src/agentproof/db/__init__.py`
- Create: `src/agentproof/db/models.py`
- Create: `src/agentproof/db/session.py`
- Create: `alembic.ini`
- Create: `alembic/env.py`
- Create: `alembic/versions/` (directory)

- [ ] **Step 1: Create DB session module**

`src/agentproof/db/__init__.py`:
```python
```

`src/agentproof/db/session.py`:
```python
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentproof.core.config import settings

engine = create_async_engine(settings.database_url, echo=False)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
```

- [ ] **Step 2: Create Agent model**

`src/agentproof/db/models.py`:
```python
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Integer, LargeBinary, Text
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    did: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verify_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verify_expires: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    verification_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    credential_jwt: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
```

- [ ] **Step 3: Set up Alembic**

`alembic.ini`:
```ini
[alembic]
script_location = alembic
sqlalchemy.url = postgresql+asyncpg://localhost:5432/agentproof

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
```

`alembic/env.py`:
```python
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from agentproof.core.config import settings
from agentproof.db.models import Base

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

Create empty versions directory:
```bash
mkdir -p alembic/versions
touch alembic/versions/.gitkeep
```

- [ ] **Step 4: Write a test that verifies the model can be instantiated**

Create `tests/core/` already exists. Add a quick model smoke test in `tests/conftest.py` — actually, add a dedicated test:

`tests/test_models.py`:
```python
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
```

- [ ] **Step 5: Run test**

Run: `pytest tests/test_models.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/db/ alembic/ alembic.ini tests/test_models.py
git commit -m "feat: database model and Alembic migration setup"
```

---

## Task 6: API Scaffolding + Health Check

**Files:**
- Create: `src/agentproof/api/__init__.py`
- Create: `src/agentproof/api/app.py`
- Create: `src/agentproof/api/deps.py`
- Create: `src/agentproof/api/routes/__init__.py`
- Create: `tests/api/__init__.py`
- Create: `tests/api/conftest.py`

- [ ] **Step 1: Write failing test for health check endpoint**

`tests/api/__init__.py`:
```python
```

`tests/api/conftest.py`:
```python
import pytest
from httpx import ASGITransport, AsyncClient

from agentproof.api.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
```

`tests/api/test_health.py`:
```python
import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/api/test_health.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentproof.api'`

- [ ] **Step 3: Implement API app factory**

`src/agentproof/api/__init__.py`:
```python
```

`src/agentproof/api/routes/__init__.py`:
```python
```

`src/agentproof/api/deps.py`:
```python
import hashlib
from datetime import datetime, timezone

from fastapi import Header, HTTPException

from agentproof.core.config import settings
from agentproof.core.crypto import verify_signature


def verify_timestamp(timestamp: str) -> datetime:
    """Parse and validate a timestamp is within the allowed tolerance."""
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


def verify_agent_signature(
    public_key: bytes, did: str, action: str, timestamp: str, signature: bytes
) -> bool:
    """Verify an Ed25519 signature for a mutation request."""
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    if not verify_signature(public_key, payload, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    return True
```

`src/agentproof/api/app.py`:
```python
from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/api/test_health.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/api/ tests/api/
git commit -m "feat: FastAPI app factory with health check"
```

---

## Task 7: Registration Endpoint

**Files:**
- Create: `src/agentproof/api/routes/register.py`
- Create: `tests/api/test_register.py`
- Modify: `src/agentproof/api/app.py`
- Modify: `tests/api/conftest.py`

- [ ] **Step 1: Update test conftest to use SQLite for testing**

Replace `tests/api/conftest.py`:
```python
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentproof.api.app import create_app
from agentproof.core.crypto import generate_keypair
from agentproof.db.models import Base
from agentproof.db.session import get_session


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
```

- [ ] **Step 2: Write failing tests for registration**

`tests/api/test_register.py`:
```python
import hashlib
from datetime import datetime, timezone

import pytest

from agentproof.core.crypto import generate_keypair, sign_payload


@pytest.mark.asyncio
async def test_register_agent_success(client):
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "display_name": "test-agent",
    })

    assert response.status_code == 200
    data = response.json()
    assert data["did"].startswith("did:key:z6Mk")
    assert data["verification_level"] == 0
    assert "credential_jwt" in data


@pytest.mark.asyncio
async def test_register_agent_bad_signature(client):
    _, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()

    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": ("aa" * 64),
        "display_name": "test-agent",
    })

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_register_agent_expired_timestamp(client):
    private_key, public_key = generate_keypair()
    timestamp = "2020-01-01T00:00:00+00:00"
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_register_duplicate_agent(client):
    private_key, public_key = generate_keypair()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    body = {
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    }

    response1 = await client.post("/agents/register", json=body)
    assert response1.status_code == 200

    response2 = await client.post("/agents/register", json=body)
    assert response2.status_code == 409
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/api/test_register.py -v`
Expected: FAIL

- [ ] **Step 4: Implement registration route**

`src/agentproof/api/routes/register.py`:
```python
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentproof.core.config import settings
from agentproof.core.credentials import issue_credential
from agentproof.core.crypto import verify_signature
from agentproof.core.did import pubkey_to_did
from agentproof.db.models import Agent
from agentproof.db.session import get_session
from agentproof.api.deps import verify_timestamp

router = APIRouter()


class RegisterRequest(BaseModel):
    public_key: str  # hex-encoded 32-byte Ed25519 public key
    timestamp: str  # ISO 8601
    signature: str  # hex-encoded 64-byte Ed25519 signature
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
    # Parse and validate inputs
    try:
        public_key = bytes.fromhex(body.public_key)
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding")

    if len(public_key) != 32:
        raise HTTPException(status_code=400, detail="Public key must be 32 bytes")
    if len(signature) != 64:
        raise HTTPException(status_code=400, detail="Signature must be 64 bytes")

    # Verify timestamp
    verify_timestamp(body.timestamp)

    # Verify signature: SHA-256(pubkey_hex + ":" + timestamp)
    payload = hashlib.sha256(f"{body.public_key}:{body.timestamp}".encode()).digest()
    if not verify_signature(public_key, payload, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Derive DID
    did = pubkey_to_did(public_key)

    # Check for duplicate
    existing = await session.execute(select(Agent).where(Agent.did == did))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Agent already registered")

    # Issue L0 credential
    issuer_private_key = request.app.state.issuer_private_key
    credential_jwt = issue_credential(
        issuer_private_key=issuer_private_key,
        issuer_did=settings.issuer_did,
        agent_did=did,
        verification_level=0,
        email_verified=False,
        ttl_days=settings.credential_ttl_days,
    )

    # Store agent
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

    return RegisterResponse(
        did=did,
        verification_level=0,
        credential_jwt=credential_jwt,
    )
```

- [ ] **Step 5: Update app.py to include the register router**

Replace `src/agentproof/api/app.py`:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(register_router, prefix="/v1")

    return app
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/api/test_register.py -v`
Expected: All 4 tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/agentproof/api/ tests/api/
git commit -m "feat: POST /agents/register endpoint with signature verification"
```

---

## Task 8: Public Verify Endpoint

**Files:**
- Create: `src/agentproof/api/routes/verify.py`
- Create: `tests/api/test_verify.py`
- Modify: `src/agentproof/api/app.py`

- [ ] **Step 1: Write failing tests**

`tests/api/test_verify.py`:
```python
import hashlib
from datetime import datetime, timezone

import pytest

from agentproof.core.crypto import generate_keypair, sign_payload


async def _register_agent(client, private_key, public_key, display_name="test-agent"):
    """Helper to register an agent and return the response data."""
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "display_name": display_name,
    })
    return response.json()


@pytest.mark.asyncio
async def test_verify_registered_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]

    response = await client.get(f"/agents/{did}/verify")
    assert response.status_code == 200
    result = response.json()
    assert result["did"] == did
    assert result["display_name"] == "test-agent"
    assert result["verification_level"] == 0
    assert result["email_verified"] is False
    assert result["valid"] is True
    assert result["revoked"] is False
    assert "created_at" in result
    assert "credential_expires" in result


@pytest.mark.asyncio
async def test_verify_unknown_did(client):
    response = await client.get("/agents/did:key:z6MkNonexistent/verify")
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/api/test_verify.py -v`
Expected: FAIL

- [ ] **Step 3: Implement verify route**

`src/agentproof/api/routes/verify.py`:
```python
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
async def verify_agent(
    did: str,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Determine credential expiry from the JWT
    credential_expires = None
    if agent.credential_jwt:
        try:
            claims = pyjwt.decode(agent.credential_jwt, options={"verify_signature": False})
            credential_expires = claims.get("exp")
            if credential_expires:
                from datetime import datetime, timezone
                credential_expires = datetime.fromtimestamp(credential_expires, tz=timezone.utc).isoformat()
        except pyjwt.InvalidTokenError:
            pass

    # Agent is valid if not revoked and credential exists
    valid = not agent.revoked and agent.credential_jwt is not None

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
```

- [ ] **Step 4: Add verify router to app**

Update `src/agentproof/api/app.py` — add import and include:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")

    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/api/test_verify.py -v`
Expected: All 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/api/ tests/api/test_verify.py
git commit -m "feat: GET /agents/{did}/verify public endpoint"
```

---

## Task 9: Credential Endpoint

**Files:**
- Create: `src/agentproof/api/routes/credential.py`
- Create: `tests/api/test_credential.py`
- Modify: `src/agentproof/api/app.py`

- [ ] **Step 1: Write failing tests**

`tests/api/test_credential.py`:
```python
import hashlib
from datetime import datetime, timezone

import pytest

from agentproof.core.crypto import generate_keypair, sign_payload


async def _register_agent(client, private_key, public_key):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    return response.json()


@pytest.mark.asyncio
async def test_get_credential(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]

    response = await client.get(f"/agents/{did}/credential")
    assert response.status_code == 200
    result = response.json()
    assert "credential_jwt" in result
    assert result["credential_jwt"] == data["credential_jwt"]


@pytest.mark.asyncio
async def test_get_credential_unknown_did(client):
    response = await client.get("/agents/did:key:z6MkNonexistent/credential")
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/api/test_credential.py -v`
Expected: FAIL

- [ ] **Step 3: Implement credential route**

`src/agentproof/api/routes/credential.py`:
```python
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
async def get_credential(
    did: str,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.credential_jwt is None:
        raise HTTPException(status_code=404, detail="No credential issued")

    return CredentialResponse(did=agent.did, credential_jwt=agent.credential_jwt)
```

- [ ] **Step 4: Add credential router to app**

Update `src/agentproof/api/app.py`:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router
from agentproof.api.routes.credential import router as credential_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")

    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/api/test_credential.py -v`
Expected: All 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/api/ tests/api/test_credential.py
git commit -m "feat: GET /agents/{did}/credential endpoint"
```

---

## Task 10: Email Verification Endpoints

**Files:**
- Create: `src/agentproof/api/routes/email.py`
- Create: `tests/api/test_email.py`
- Modify: `src/agentproof/api/app.py`

- [ ] **Step 1: Write failing tests**

`tests/api/test_email.py`:
```python
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from agentproof.core.crypto import generate_keypair, sign_payload


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

    with patch("agentproof.api.routes.email.send_verification_email", new_callable=AsyncMock) as mock_send:
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
    # Register without email
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

    # Trigger verify-email to store a code
    ts1, sig1 = _sign_mutation(private_key, did, "verify-email")
    captured_code = {}

    async def fake_send(email, code):
        captured_code["code"] = code
        return True

    with patch("agentproof.api.routes.email.send_verification_email", side_effect=fake_send):
        await client.post(f"/agents/{did}/verify-email", json={
            "timestamp": ts1,
            "signature": sig1.hex(),
        })

    # Confirm with the captured code
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
    with patch("agentproof.api.routes.email.send_verification_email", new_callable=AsyncMock) as mock_send:
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/api/test_email.py -v`
Expected: FAIL

- [ ] **Step 3: Implement email routes**

`src/agentproof/api/routes/email.py`:
```python
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
from agentproof.core.did import did_to_pubkey
from agentproof.db.models import Agent
from agentproof.db.session import get_session

router = APIRouter()


class VerifyEmailRequest(BaseModel):
    timestamp: str
    signature: str  # hex


class ConfirmEmailRequest(BaseModel):
    code: str
    timestamp: str
    signature: str  # hex


class ConfirmEmailResponse(BaseModel):
    verification_level: int
    credential_jwt: str


async def send_verification_email(email: str, code: str) -> bool:
    """Send a verification code via Resend."""
    resend.api_key = settings.resend_api_key
    resend.Emails.send({
        "from": settings.resend_from_email,
        "to": [email],
        "subject": "AgentProof Email Verification",
        "text": f"Your verification code is: {code}\n\nThis code expires in 10 minutes.",
    })
    return True


@router.post("/agents/{did:path}/verify-email")
async def verify_email(
    did: str,
    body: VerifyEmailRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    # Look up agent
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if not agent.owner_email:
        raise HTTPException(status_code=400, detail="No email on file")

    # Verify signature
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "verify-email", body.timestamp, signature)

    # Generate 6-digit code
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    # Store hash and expiry
    agent.email_verify_token = code_hash
    agent.email_verify_expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    await session.commit()

    # Send email
    await send_verification_email(agent.owner_email, code)

    return {"message": "Verification code sent"}


@router.post("/agents/{did:path}/confirm-email", response_model=ConfirmEmailResponse)
async def confirm_email(
    did: str,
    body: ConfirmEmailRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    # Look up agent
    result = await session.execute(select(Agent).where(Agent.did == did))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Verify signature
    verify_timestamp(body.timestamp)
    try:
        signature = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature hex")
    verify_agent_signature(agent.public_key, did, "confirm-email", body.timestamp, signature)

    # Verify code
    if not agent.email_verify_token or not agent.email_verify_expires:
        raise HTTPException(status_code=400, detail="No pending verification")

    if datetime.now(timezone.utc) > agent.email_verify_expires:
        raise HTTPException(status_code=401, detail="Verification code expired")

    code_hash = hashlib.sha256(body.code.encode()).hexdigest()
    if code_hash != agent.email_verify_token:
        raise HTTPException(status_code=401, detail="Invalid verification code")

    # Upgrade to L1
    agent.email_verified = True
    agent.verification_level = 1
    agent.email_verify_token = None
    agent.email_verify_expires = None
    agent.last_verified_at = datetime.now(timezone.utc)

    # Re-issue credential
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

    return ConfirmEmailResponse(
        verification_level=1,
        credential_jwt=credential_jwt,
    )
```

- [ ] **Step 4: Add email router to app**

Update `src/agentproof/api/app.py`:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router
from agentproof.api.routes.credential import router as credential_router
from agentproof.api.routes.email import router as email_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")
    app.include_router(email_router, prefix="/v1")

    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/api/test_email.py -v`
Expected: All 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/api/ tests/api/test_email.py
git commit -m "feat: email verification endpoints (verify-email + confirm-email)"
```

---

## Task 11: Revoke and Delete Endpoints

**Files:**
- Create: `src/agentproof/api/routes/manage.py`
- Create: `tests/api/test_manage.py`
- Modify: `src/agentproof/api/app.py`

- [ ] **Step 1: Write failing tests**

`tests/api/test_manage.py`:
```python
import hashlib
from datetime import datetime, timezone

import pytest

from agentproof.core.crypto import generate_keypair, sign_payload


async def _register_agent(client, private_key, public_key):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    response = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    })
    return response.json()


def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature


@pytest.mark.asyncio
async def test_revoke_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]

    timestamp, signature = _sign_mutation(private_key, did, "revoke")
    response = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    assert response.status_code == 200
    assert response.json()["revoked"] is True

    # Verify shows revoked
    verify_resp = await client.get(f"/agents/{did}/verify")
    assert verify_resp.json()["revoked"] is True
    assert verify_resp.json()["valid"] is False


@pytest.mark.asyncio
async def test_revoke_wrong_signature(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]

    other_private, _ = generate_keypair()
    timestamp, signature = _sign_mutation(other_private, did, "revoke")
    response = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_agent(client):
    private_key, public_key = generate_keypair()
    data = await _register_agent(client, private_key, public_key)
    did = data["did"]

    timestamp, signature = _sign_mutation(private_key, did, "delete")
    response = await client.delete(f"/agents/{did}", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    assert response.status_code == 200

    # Verify returns 404
    verify_resp = await client.get(f"/agents/{did}/verify")
    assert verify_resp.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/api/test_manage.py -v`
Expected: FAIL

- [ ] **Step 3: Implement manage routes**

`src/agentproof/api/routes/manage.py`:
```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentproof.api.deps import verify_agent_signature, verify_timestamp
from agentproof.db.models import Agent
from agentproof.db.session import get_session

router = APIRouter()


class SignedRequest(BaseModel):
    timestamp: str
    signature: str  # hex


@router.post("/agents/{did:path}/revoke")
async def revoke_agent(
    did: str,
    body: SignedRequest,
    session: AsyncSession = Depends(get_session),
):
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
async def delete_agent(
    did: str,
    body: SignedRequest,
    session: AsyncSession = Depends(get_session),
):
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
```

- [ ] **Step 4: Add manage router to app**

Update `src/agentproof/api/app.py`:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router
from agentproof.api.routes.credential import router as credential_router
from agentproof.api.routes.email import router as email_router
from agentproof.api.routes.manage import router as manage_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")
    app.include_router(email_router, prefix="/v1")
    app.include_router(manage_router, prefix="/v1")

    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/api/test_manage.py -v`
Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/api/ tests/api/test_manage.py
git commit -m "feat: revoke and delete agent endpoints"
```

---

## Task 12: Well-Known DID Document Endpoint

**Files:**
- Create: `src/agentproof/api/routes/well_known.py`
- Create: `tests/api/test_well_known.py`
- Modify: `src/agentproof/api/app.py`

- [ ] **Step 1: Write failing tests**

`tests/api/test_well_known.py`:
```python
import pytest

from agentproof.core.did import pubkey_to_did


@pytest.mark.asyncio
async def test_well_known_did_json(client, issuer_keypair):
    response = await client.get("/.well-known/did.json")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "did:web:agentproof.dev"
    assert "verificationMethod" in data
    assert len(data["verificationMethod"]) == 1
    method = data["verificationMethod"][0]
    assert method["type"] == "Ed25519VerificationKey2020"
    assert "publicKeyMultibase" in method
```

Note: The well-known endpoint is NOT under `/v1` prefix — it's at the root. Update the test client:

Actually, we need a separate client fixture or use the app directly. Let's adjust the test:

```python
import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_well_known_did_json(app, issuer_keypair):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/did.json")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "did:web:agentproof.dev"
    assert "verificationMethod" in data
    assert len(data["verificationMethod"]) == 1
    method = data["verificationMethod"][0]
    assert method["type"] == "Ed25519VerificationKey2020"
    assert "publicKeyMultibase" in method
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/api/test_well_known.py -v`
Expected: FAIL

- [ ] **Step 3: Implement well-known route**

`src/agentproof/api/routes/well_known.py`:
```python
import base58
from fastapi import APIRouter, Request

from agentproof.core.config import settings

router = APIRouter()

# Multicodec prefix for Ed25519 public key
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


@router.get("/.well-known/did.json")
async def did_document(request: Request):
    issuer_public_key = request.app.state.issuer_public_key
    # Encode public key as multibase (base58btc with 'z' prefix)
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + issuer_public_key
    public_key_multibase = "z" + base58.b58encode(multicodec_bytes).decode("ascii")

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": settings.issuer_did,
        "verificationMethod": [
            {
                "id": f"{settings.issuer_did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": settings.issuer_did,
                "publicKeyMultibase": public_key_multibase,
            }
        ],
        "authentication": [f"{settings.issuer_did}#key-1"],
        "assertionMethod": [f"{settings.issuer_did}#key-1"],
    }
```

- [ ] **Step 4: Add well-known router to app (no prefix)**

Update `src/agentproof/api/app.py`:
```python
from fastapi import FastAPI

from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router
from agentproof.api.routes.credential import router as credential_router
from agentproof.api.routes.email import router as email_router
from agentproof.api.routes.manage import router as manage_router
from agentproof.api.routes.well_known import router as well_known_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(well_known_router)
    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")
    app.include_router(email_router, prefix="/v1")
    app.include_router(manage_router, prefix="/v1")

    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/api/test_well_known.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/api/ tests/api/test_well_known.py
git commit -m "feat: /.well-known/did.json issuer DID document"
```

---

## Task 13: CLI — Keygen Command

**Files:**
- Create: `src/agentproof/cli/__init__.py`
- Create: `src/agentproof/cli/main.py`
- Create: `src/agentproof/cli/keygen.py`
- Create: `tests/cli/__init__.py`
- Create: `tests/cli/conftest.py`
- Create: `tests/cli/test_keygen.py`

- [ ] **Step 1: Write failing tests**

`tests/cli/__init__.py`:
```python
```

`tests/cli/conftest.py`:
```python
import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    return CliRunner()
```

`tests/cli/test_keygen.py`:
```python
import os

from agentproof.cli.main import cli


def test_keygen_creates_files(runner, tmp_path):
    result = runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "agent.pub").exists()
    assert (tmp_path / "agent.key").exists()
    # Public key file should contain 64 hex chars (32 bytes)
    pub_content = (tmp_path / "agent.pub").read_text().strip()
    assert len(pub_content) == 64


def test_keygen_refuses_overwrite(runner, tmp_path):
    # First keygen
    runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path)])
    # Second keygen should refuse
    result = runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path)])
    assert result.exit_code != 0 or "already exists" in result.output


def test_keygen_force_overwrite(runner, tmp_path):
    runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path)])
    result = runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path), "--force"])
    assert result.exit_code == 0


def test_keygen_key_file_permissions(runner, tmp_path):
    result = runner.invoke(cli, ["keygen", "--config-dir", str(tmp_path)])
    assert result.exit_code == 0
    key_path = tmp_path / "agent.key"
    mode = oct(key_path.stat().st_mode & 0o777)
    assert mode == "0o600"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_keygen.py -v`
Expected: FAIL

- [ ] **Step 3: Implement CLI main and keygen**

`src/agentproof/cli/__init__.py`:
```python
```

`src/agentproof/cli/main.py`:
```python
import os

import click


@click.group()
@click.option("--config-dir", default=os.path.expanduser("~/.agentproof"), help="Config directory")
@click.option("--api-url", default="https://api.agentproof.dev/v1", help="API base URL")
@click.pass_context
def cli(ctx, config_dir, api_url):
    """AgentProof: Cryptographic proof that a human stands behind an AI agent."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["api_url"] = api_url
```

`src/agentproof/cli/keygen.py`:
```python
import os
import stat

import click

from agentproof.cli.main import cli
from agentproof.core.crypto import generate_keypair


@cli.command()
@click.option("--force", is_flag=True, help="Overwrite existing keys")
@click.pass_context
def keygen(ctx, force):
    """Generate a new Ed25519 keypair."""
    config_dir = ctx.obj["config_dir"]
    os.makedirs(config_dir, exist_ok=True)

    key_path = os.path.join(config_dir, "agent.key")
    pub_path = os.path.join(config_dir, "agent.pub")

    if os.path.exists(key_path) and not force:
        click.echo(f"Key already exists at {key_path}. Use --force to overwrite.")
        ctx.exit(1)
        return

    private_key, public_key = generate_keypair()

    # Write private key (raw bytes for MVP — encrypted at rest is post-MVP polish)
    with open(key_path, "wb") as f:
        f.write(private_key)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    # Write public key as hex
    with open(pub_path, "w") as f:
        f.write(public_key.hex())

    click.echo(f"Keypair generated:")
    click.echo(f"  Private key: {key_path}")
    click.echo(f"  Public key:  {pub_path}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/cli/test_keygen.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/cli/ tests/cli/
git commit -m "feat: CLI keygen command"
```

---

## Task 14: CLI — Register Command

**Files:**
- Create: `src/agentproof/cli/register.py`
- Create: `tests/cli/test_register.py`

- [ ] **Step 1: Write failing tests**

`tests/cli/test_register.py`:
```python
import hashlib
import json
import os
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from agentproof.cli.main import cli
from agentproof.core.crypto import generate_keypair, sign_payload


def _setup_keys(tmp_path):
    """Write a keypair to the tmp config dir."""
    private_key, public_key = generate_keypair()
    (tmp_path / "agent.key").write_bytes(private_key)
    (tmp_path / "agent.pub").write_text(public_key.hex())
    return private_key, public_key


def test_register_success(runner, tmp_path):
    private_key, public_key = _setup_keys(tmp_path)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "did": "did:key:z6MkTest",
        "verification_level": 0,
        "credential_jwt": "eyJ...",
    }

    with patch("agentproof.cli.register.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, [
            "--config-dir", str(tmp_path),
            "register", "--name", "my-agent",
        ])

    assert result.exit_code == 0
    assert "did:key:z6MkTest" in result.output
    # Config file should be written
    assert (tmp_path / "config.toml").exists()
    # Credential should be saved
    assert (tmp_path / "credential.jwt").exists()


def test_register_no_keys(runner, tmp_path):
    result = runner.invoke(cli, [
        "--config-dir", str(tmp_path),
        "register", "--name", "my-agent",
    ])
    assert result.exit_code != 0 or "No keypair found" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_register.py -v`
Expected: FAIL

- [ ] **Step 3: Implement register command**

`src/agentproof/cli/register.py`:
```python
import hashlib
import os
from datetime import datetime, timezone

import click
import httpx
import tomli_w

from agentproof.cli.main import cli
from agentproof.core.crypto import sign_payload


@cli.command()
@click.option("--name", default=None, help="Display name for the agent")
@click.option("--email", default=None, help="Owner email for L1 verification")
@click.pass_context
def register(ctx, name, email):
    """Register your agent with AgentProof."""
    config_dir = ctx.obj["config_dir"]
    api_url = ctx.obj["api_url"]

    key_path = os.path.join(config_dir, "agent.key")
    pub_path = os.path.join(config_dir, "agent.pub")

    if not os.path.exists(key_path) or not os.path.exists(pub_path):
        click.echo("No keypair found. Run `agentproof keygen` first.")
        ctx.exit(1)
        return

    private_key = open(key_path, "rb").read()
    public_key_hex = open(pub_path, "r").read().strip()

    # Build signed registration payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key_hex}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    body = {
        "public_key": public_key_hex,
        "timestamp": timestamp,
        "signature": signature.hex(),
    }
    if name:
        body["display_name"] = name
    if email:
        body["owner_email"] = email

    response = httpx.post(f"{api_url}/agents/register", json=body)
    if response.status_code != 200:
        click.echo(f"Registration failed: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return

    data = response.json()
    did = data["did"]
    credential_jwt = data["credential_jwt"]

    # Save config
    config = {"api_url": api_url, "did": did}
    with open(os.path.join(config_dir, "config.toml"), "wb") as f:
        tomli_w.dump(config, f)

    # Save credential
    with open(os.path.join(config_dir, "credential.jwt"), "w") as f:
        f.write(credential_jwt)

    click.echo(f"Registered {did}  (Level {data['verification_level']})")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/cli/test_register.py -v`
Expected: All 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/cli/register.py tests/cli/test_register.py
git commit -m "feat: CLI register command"
```

---

## Task 15: CLI — Verify Command

**Files:**
- Create: `src/agentproof/cli/verify.py`
- Create: `tests/cli/test_verify.py`

- [ ] **Step 1: Write failing tests**

`tests/cli/test_verify.py`:
```python
from unittest.mock import patch, MagicMock

from agentproof.cli.main import cli


def test_verify_agent_success(runner):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "did": "did:key:z6MkTest",
        "display_name": "my-agent",
        "verification_level": 1,
        "email_verified": True,
        "valid": True,
        "revoked": False,
        "created_at": "2026-04-01T00:00:00+00:00",
        "credential_expires": "2026-07-01T00:00:00+00:00",
    }

    with patch("agentproof.cli.verify.httpx.get", return_value=mock_response):
        result = runner.invoke(cli, ["verify", "did:key:z6MkTest"])

    assert result.exit_code == 0
    assert "my-agent" in result.output
    assert "Level: 1" in result.output
    assert "Valid" in result.output


def test_verify_agent_not_found(runner):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"detail": "Agent not found"}

    with patch("agentproof.cli.verify.httpx.get", return_value=mock_response):
        result = runner.invoke(cli, ["verify", "did:key:z6MkNotFound"])

    assert result.exit_code != 0 or "not found" in result.output.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_verify.py -v`
Expected: FAIL

- [ ] **Step 3: Implement verify command**

`src/agentproof/cli/verify.py`:
```python
import click
import httpx

from agentproof.cli.main import cli


@cli.command()
@click.argument("did")
@click.pass_context
def verify(ctx, did):
    """Verify an agent by DID."""
    api_url = ctx.obj["api_url"]

    response = httpx.get(f"{api_url}/agents/{did}/verify")
    if response.status_code == 404:
        click.echo(f"Agent not found: {did}")
        ctx.exit(1)
        return
    if response.status_code != 200:
        click.echo(f"Error: {response.text}")
        ctx.exit(1)
        return

    data = response.json()
    level_desc = {0: "registered", 1: "email verified"}
    level = data["verification_level"]

    click.echo(f"  Agent: {data.get('display_name') or '(unnamed)'}")
    click.echo(f"  DID:   {data['did']}")
    click.echo(f"  Level: {level} ({level_desc.get(level, 'unknown')})")
    valid_mark = "Valid" if data["valid"] else "INVALID"
    if data["revoked"]:
        valid_mark = "REVOKED"
    expires = data.get("credential_expires", "unknown")
    click.echo(f"  Status: {valid_mark} (expires {expires})")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/cli/test_verify.py -v`
Expected: All 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/cli/verify.py tests/cli/test_verify.py
git commit -m "feat: CLI verify command"
```

---

## Task 16: CLI — Email Verification Commands

**Files:**
- Create: `src/agentproof/cli/email.py`
- Create: `tests/cli/test_email.py`

- [ ] **Step 1: Write failing tests**

`tests/cli/test_email.py`:
```python
import os
from unittest.mock import patch, MagicMock

import tomli_w

from agentproof.cli.main import cli
from agentproof.core.crypto import generate_keypair


def _setup_registered_agent(tmp_path):
    private_key, public_key = generate_keypair()
    (tmp_path / "agent.key").write_bytes(private_key)
    (tmp_path / "agent.pub").write_text(public_key.hex())
    config = {"api_url": "https://api.agentproof.dev/v1", "did": "did:key:z6MkTest"}
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump(config, f)
    return private_key, public_key


def test_verify_email_sends_code(runner, tmp_path):
    _setup_registered_agent(tmp_path)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Verification code sent"}

    with patch("agentproof.cli.email.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, [
            "--config-dir", str(tmp_path),
            "verify-email", "--email", "test@example.com",
        ])

    assert result.exit_code == 0
    assert "code sent" in result.output.lower() or "Check your email" in result.output


def test_confirm_email_success(runner, tmp_path):
    _setup_registered_agent(tmp_path)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "verification_level": 1,
        "credential_jwt": "eyJ...",
    }

    with patch("agentproof.cli.email.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, [
            "--config-dir", str(tmp_path),
            "confirm-email", "--code", "123456",
        ])

    assert result.exit_code == 0
    assert "Level 1" in result.output or "verified" in result.output.lower()
    # Credential should be updated
    assert (tmp_path / "credential.jwt").read_text() == "eyJ..."
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_email.py -v`
Expected: FAIL

- [ ] **Step 3: Implement email commands**

`src/agentproof/cli/email.py`:
```python
import hashlib
import os
from datetime import datetime, timezone

import click
import httpx

from agentproof.cli.main import cli
from agentproof.core.crypto import sign_payload


def _load_agent_context(ctx):
    """Load private key and config for signed requests."""
    config_dir = ctx.obj["config_dir"]
    key_path = os.path.join(config_dir, "agent.key")
    config_path = os.path.join(config_dir, "config.toml")

    if not os.path.exists(key_path) or not os.path.exists(config_path):
        click.echo("No registered agent found. Run `agentproof register` first.")
        ctx.exit(1)
        return None, None, None

    private_key = open(key_path, "rb").read()

    if hasattr(__builtins__, "__import__"):
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
    else:
        import tomllib

    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    return private_key, config["did"], config.get("api_url", ctx.obj["api_url"])


def _sign_mutation(private_key, did, action):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:{action}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)
    return timestamp, signature


@cli.command("verify-email")
@click.option("--email", required=True, help="Email address to verify")
@click.pass_context
def verify_email(ctx, email):
    """Send a verification code to your email."""
    private_key, did, api_url = _load_agent_context(ctx)
    if private_key is None:
        return

    timestamp, signature = _sign_mutation(private_key, did, "verify-email")

    response = httpx.post(f"{api_url}/agents/{did}/verify-email", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return

    click.echo("Check your email for a 6-digit code.")


@cli.command("confirm-email")
@click.option("--code", required=True, help="6-digit verification code")
@click.pass_context
def confirm_email(ctx, code):
    """Submit your verification code to upgrade to Level 1."""
    config_dir = ctx.obj["config_dir"]
    private_key, did, api_url = _load_agent_context(ctx)
    if private_key is None:
        return

    timestamp, signature = _sign_mutation(private_key, did, "confirm-email")

    response = httpx.post(f"{api_url}/agents/{did}/confirm-email", json={
        "code": code,
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return

    data = response.json()

    # Update saved credential
    with open(os.path.join(config_dir, "credential.jwt"), "w") as f:
        f.write(data["credential_jwt"])

    click.echo(f"Email verified. Upgraded to Level {data['verification_level']}.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/cli/test_email.py -v`
Expected: All 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentproof/cli/email.py tests/cli/test_email.py
git commit -m "feat: CLI verify-email and confirm-email commands"
```

---

## Task 17: CLI — Revoke and Credential Export Commands

**Files:**
- Create: `src/agentproof/cli/revoke.py`
- Create: `src/agentproof/cli/credential.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/cli/test_verify.py` (or create separate files). Let's create dedicated test files:

`tests/cli/test_revoke.py`:
```python
from unittest.mock import patch, MagicMock

import tomli_w

from agentproof.cli.main import cli
from agentproof.core.crypto import generate_keypair


def _setup_registered_agent(tmp_path):
    private_key, public_key = generate_keypair()
    (tmp_path / "agent.key").write_bytes(private_key)
    (tmp_path / "agent.pub").write_text(public_key.hex())
    config = {"api_url": "https://api.agentproof.dev/v1", "did": "did:key:z6MkTest"}
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump(config, f)
    return private_key


def test_revoke_success(runner, tmp_path):
    _setup_registered_agent(tmp_path)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"did": "did:key:z6MkTest", "revoked": True}

    with patch("agentproof.cli.revoke.httpx.post", return_value=mock_response):
        result = runner.invoke(cli, ["--config-dir", str(tmp_path), "revoke"])

    assert result.exit_code == 0
    assert "revoked" in result.output.lower()
```

`tests/cli/test_credential.py`:
```python
import json

from agentproof.cli.main import cli


def test_credential_jwt(runner, tmp_path):
    (tmp_path / "credential.jwt").write_text("eyJhbGciOiJFZERTQSJ9.test.sig")
    config_content = b""
    import tomli_w
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump({"did": "did:key:z6MkTest", "api_url": "http://test"}, f)

    result = runner.invoke(cli, [
        "--config-dir", str(tmp_path),
        "credential", "--format", "jwt",
    ])

    assert result.exit_code == 0
    assert "eyJhbGciOiJFZERTQSJ9.test.sig" in result.output


def test_credential_agent_card(runner, tmp_path):
    (tmp_path / "credential.jwt").write_text("eyJhbGciOiJFZERTQSJ9.test.sig")
    import tomli_w
    with open(tmp_path / "config.toml", "wb") as f:
        tomli_w.dump({"did": "did:key:z6MkTest", "api_url": "http://test"}, f)

    result = runner.invoke(cli, [
        "--config-dir", str(tmp_path),
        "credential", "--format", "agent-card",
    ])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["id"] == "did:key:z6MkTest"
    assert "agentproof" in data["verification"]["issuer"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_revoke.py tests/cli/test_credential.py -v`
Expected: FAIL

- [ ] **Step 3: Implement revoke command**

`src/agentproof/cli/revoke.py`:
```python
import hashlib
import os
from datetime import datetime, timezone

import click
import httpx

from agentproof.cli.main import cli
from agentproof.core.crypto import sign_payload


@cli.command()
@click.pass_context
def revoke(ctx):
    """Revoke your agent's credential."""
    config_dir = ctx.obj["config_dir"]
    key_path = os.path.join(config_dir, "agent.key")
    config_path = os.path.join(config_dir, "config.toml")

    if not os.path.exists(key_path) or not os.path.exists(config_path):
        click.echo("No registered agent found. Run `agentproof register` first.")
        ctx.exit(1)
        return

    private_key = open(key_path, "rb").read()

    import sys
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    did = config["did"]
    api_url = config.get("api_url", ctx.obj["api_url"])

    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{did}:revoke:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    response = httpx.post(f"{api_url}/agents/{did}/revoke", json={
        "timestamp": timestamp,
        "signature": signature.hex(),
    })

    if response.status_code != 200:
        click.echo(f"Error: {response.json().get('detail', response.text)}")
        ctx.exit(1)
        return

    click.echo("Agent credential revoked.")
```

- [ ] **Step 4: Implement credential export command**

`src/agentproof/cli/credential.py`:
```python
import json
import os
import sys

import click

from agentproof.cli.main import cli


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["jwt", "agent-card"]), default="jwt", help="Output format")
@click.pass_context
def credential(ctx, fmt):
    """Export your agent's credential."""
    config_dir = ctx.obj["config_dir"]
    cred_path = os.path.join(config_dir, "credential.jwt")
    config_path = os.path.join(config_dir, "config.toml")

    if not os.path.exists(cred_path):
        click.echo("No credential found. Run `agentproof register` first.")
        ctx.exit(1)
        return

    credential_jwt = open(cred_path, "r").read().strip()

    if fmt == "jwt":
        click.echo(credential_jwt)
        return

    # agent-card format
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    agent_card = {
        "id": config["did"],
        "verification": {
            "type": "AgentProof",
            "issuer": "did:web:agentproof.dev",
            "credential": credential_jwt,
        },
    }
    click.echo(json.dumps(agent_card, indent=2))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/cli/test_revoke.py tests/cli/test_credential.py -v`
Expected: All 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentproof/cli/revoke.py src/agentproof/cli/credential.py tests/cli/test_revoke.py tests/cli/test_credential.py
git commit -m "feat: CLI revoke and credential export commands"
```

---

## Task 18: CLI Command Registration

**Files:**
- Modify: `src/agentproof/cli/main.py`

The Click commands are defined in separate files but need to be imported so they register with the CLI group.

- [ ] **Step 1: Update main.py to import all commands**

Replace `src/agentproof/cli/main.py`:
```python
import os

import click


@click.group()
@click.option("--config-dir", default=os.path.expanduser("~/.agentproof"), help="Config directory")
@click.option("--api-url", default="https://api.agentproof.dev/v1", help="API base URL")
@click.pass_context
def cli(ctx, config_dir, api_url):
    """AgentProof: Cryptographic proof that a human stands behind an AI agent."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    ctx.obj["api_url"] = api_url


# Import commands to register them with the CLI group
import agentproof.cli.keygen  # noqa: E402, F401
import agentproof.cli.register  # noqa: E402, F401
import agentproof.cli.verify  # noqa: E402, F401
import agentproof.cli.email  # noqa: E402, F401
import agentproof.cli.revoke  # noqa: E402, F401
import agentproof.cli.credential  # noqa: E402, F401
```

- [ ] **Step 2: Test that all commands are registered**

Run: `python -m agentproof.cli.main --help`
Expected output should list: keygen, register, verify, verify-email, confirm-email, revoke, credential

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/agentproof/cli/main.py
git commit -m "feat: register all CLI commands in main group"
```

---

## Task 19: API Server Entrypoint and Lifespan

**Files:**
- Modify: `src/agentproof/api/app.py`

The API needs to load the issuer keypair from environment variables on startup.

- [ ] **Step 1: Write test for app startup with issuer key**

Add to `tests/api/test_health.py`:
```python
import pytest
from httpx import ASGITransport, AsyncClient

from agentproof.api.app import create_app
from agentproof.core.crypto import generate_keypair


@pytest.mark.asyncio
async def test_health_check_standalone():
    """Test health check works without DB override (app creates its own state)."""
    private_key, public_key = generate_keypair()
    import os
    os.environ["AGENTPROOF_ISSUER_PRIVATE_KEY_HEX"] = private_key.hex()
    try:
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.status_code == 200
    finally:
        del os.environ["AGENTPROOF_ISSUER_PRIVATE_KEY_HEX"]
```

- [ ] **Step 2: Update app.py with lifespan and issuer key loading**

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agentproof.core.config import Settings
from agentproof.api.routes.register import router as register_router
from agentproof.api.routes.verify import router as verify_router
from agentproof.api.routes.credential import router as credential_router
from agentproof.api.routes.email import router as email_router
from agentproof.api.routes.manage import router as manage_router
from agentproof.api.routes.well_known import router as well_known_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load issuer keypair from config if not already set (tests set it directly)
    if not hasattr(app.state, "issuer_private_key") or not app.state.issuer_private_key:
        s = Settings()
        if s.issuer_private_key_hex:
            from nacl.signing import SigningKey
            private_key = bytes.fromhex(s.issuer_private_key_hex)
            signing_key = SigningKey(private_key)
            app.state.issuer_private_key = private_key
            app.state.issuer_public_key = bytes(signing_key.verify_key)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentProof",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(well_known_router)
    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")
    app.include_router(email_router, prefix="/v1")
    app.include_router(manage_router, prefix="/v1")

    return app


app = create_app()
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/agentproof/api/app.py tests/api/test_health.py
git commit -m "feat: API lifespan with issuer key loading"
```

---

## Task 20: Deployment — Dockerfile and fly.toml

**Files:**
- Create: `Dockerfile`
- Create: `fly.toml`

- [ ] **Step 1: Create Dockerfile**

`Dockerfile`:
```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "agentproof.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 2: Create fly.toml**

`fly.toml`:
```toml
app = "agentproof-api"
primary_region = "sjc"

[build]

[env]
  PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1

[[vm]]
  memory = "512mb"
  cpu_kind = "shared"
  cpus = 1
```

- [ ] **Step 3: Verify Docker build**

Run:
```bash
docker build -t agentproof-api .
```
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add Dockerfile fly.toml
git commit -m "feat: Dockerfile and fly.toml for Fly.io deployment"
```

---

## Task 21: Full Integration Test

**Files:**
- Create: `tests/test_integration.py`

End-to-end test of the complete L0 → L1 flow through the API.

- [ ] **Step 1: Write integration test**

`tests/test_integration.py`:
```python
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
    """Complete flow: register → verify → get credential → email verify → confirm → verify again."""
    private_key, public_key = generate_keypair()

    # 1. Register (L0)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = hashlib.sha256(f"{public_key.hex()}:{timestamp}".encode()).digest()
    signature = sign_payload(private_key, payload)

    reg_resp = await client.post("/agents/register", json={
        "public_key": public_key.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
        "display_name": "integration-test-agent",
        "owner_email": "test@example.com",
    })
    assert reg_resp.status_code == 200
    did = reg_resp.json()["did"]
    assert reg_resp.json()["verification_level"] == 0

    # 2. Public verify — should show L0
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
            "timestamp": ts1,
            "signature": sig1.hex(),
        })
    assert email_resp.status_code == 200

    # 5. Confirm email — upgrade to L1
    ts2, sig2 = _sign_mutation(private_key, did, "confirm-email")
    confirm_resp = await client.post(f"/agents/{did}/confirm-email", json={
        "code": captured_code["code"],
        "timestamp": ts2,
        "signature": sig2.hex(),
    })
    assert confirm_resp.status_code == 200
    assert confirm_resp.json()["verification_level"] == 1

    # 6. Verify again — should show L1
    verify_resp2 = await client.get(f"/agents/{did}/verify")
    assert verify_resp2.json()["verification_level"] == 1
    assert verify_resp2.json()["email_verified"] is True
    assert verify_resp2.json()["valid"] is True

    # 7. Revoke
    ts3, sig3 = _sign_mutation(private_key, did, "revoke")
    revoke_resp = await client.post(f"/agents/{did}/revoke", json={
        "timestamp": ts3,
        "signature": sig3.hex(),
    })
    assert revoke_resp.status_code == 200

    # 8. Verify shows revoked
    verify_resp3 = await client.get(f"/agents/{did}/verify")
    assert verify_resp3.json()["revoked"] is True
    assert verify_resp3.json()["valid"] is False
```

- [ ] **Step 2: Run integration test**

Run: `pytest tests/test_integration.py -v`
Expected: PASS

- [ ] **Step 3: Run full test suite one final time**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: full L0 → L1 integration test"
```

---

## Deployment Steps (Manual)

These are run once by the developer, not by the agentic worker:

1. **Create Fly.io app:** `fly launch --no-deploy`
2. **Create Postgres:** `fly postgres create --name agentproof-db`
3. **Attach DB:** `fly postgres attach agentproof-db`
4. **Generate issuer keypair:**
   ```bash
   python -c "from agentproof.core.crypto import generate_keypair; k,p = generate_keypair(); print(f'Private: {k.hex()}\nPublic: {p.hex()}')"
   ```
5. **Set secrets:**
   ```bash
   fly secrets set AGENTPROOF_ISSUER_PRIVATE_KEY_HEX=<private_key_hex>
   fly secrets set AGENTPROOF_RESEND_API_KEY=<resend_key>
   ```
6. **Run migration:**
   ```bash
   fly ssh console -C "alembic upgrade head"
   ```
7. **Deploy:** `fly deploy`
8. **Verify:** `curl https://agentproof-api.fly.dev/health`
