# AgentProof MVP Design Spec

**Date:** 2026-04-02
**Timeline:** 14 days (side project)
**Scope:** API + CLI only (web app deferred)
**Stack:** FastAPI + PostgreSQL + Python CLI
**Deploy:** Fly.io

---

## What You're Shipping

A service where anyone can register an AI agent's Ed25519 public key, optionally verify their email, and get back a signed credential (JWT) proving "a human controls this agent." Anyone can verify any agent via a public API endpoint — no auth required.

**One-liner:** Cryptographic proof that a human stands behind an AI agent. Free, open-source, cross-platform.

---

## MVP Scope Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Surfaces | API + CLI only | Web app deferred to reduce scope |
| Credential format | JWT only | JSON-LD deferred — JWT covers 90% of value, JSON-LD adds 2-3 days |
| Project structure | Monorepo, single package | Simplest for solo dev; split later if needed |
| Platform API keys | Deferred | Public verify covers core use case; batch/keys when a platform asks |
| Email provider | Resend | Free tier (100/day) is plenty; simple API |
| Hosting | Fly.io | Cheap, fast deploy, PostgreSQL included |
| OpenClaw/DAP coupling | None | Completely separate identity system |
| Abuse prevention | Post-MVP | Ed25519 signature on registration is natural barrier; rate limiting later |
| Auto-renewal | Post-MVP | Agents re-register when credentials expire (90-day TTL) |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   agentproof/                     │
│                                                   │
│  src/agentproof/                                  │
│  ├── api/          FastAPI app, routes, middleware │
│  ├── cli/          Click CLI commands             │
│  ├── core/         Crypto, DID, credentials       │
│  └── db/           SQLAlchemy models, migrations  │
│                                                   │
│  tests/                                           │
│  alembic/          DB migrations                  │
│  pyproject.toml                                   │
│  Dockerfile                                       │
│  fly.toml                                         │
└──────────────────────────────────────────────────┘
```

Single Python package. CLI and API share `core/` for crypto, DID derivation, and credential logic. CLI communicates with the deployed API over HTTP (does not import API/DB modules directly).

---

## Data Model

Single table for MVP (no `api_keys` table):

```
agents
├── id                   UUID, PK
├── did                  TEXT, UNIQUE       -- "did:key:z6Mk..."
├── public_key           BYTEA              -- 32-byte Ed25519 pubkey
├── display_name         TEXT, nullable
├── owner_email          TEXT, nullable
├── email_verified       BOOLEAN, default false
├── email_verify_token   TEXT, nullable     -- SHA-256 hash of 6-digit code
├── email_verify_expires TIMESTAMPTZ, nullable
├── verification_level   INT, default 0    -- 0 or 1
├── credential_jwt       TEXT, nullable     -- signed VC (JWT)
├── revoked              BOOLEAN, default false
├── created_at           TIMESTAMPTZ
├── updated_at           TIMESTAMPTZ
└── last_verified_at     TIMESTAMPTZ, nullable
```

No PII beyond optional email. No credential content stored beyond the signed JWT.

---

## API Endpoints

Base URL: `https://api.agentproof.dev/v1`

### Public (no auth)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agents/register` | Register agent. Body: `{ public_key, display_name?, owner_email?, timestamp, signature }`. Returns DID + L0 credential. |
| `GET` | `/agents/{did}/verify` | Public verification. Returns `{ did, display_name, verification_level, email_verified, valid, revoked, created_at, credential_expires }`. |
| `GET` | `/agents/{did}/credential` | Get the agent's signed VC (JWT). |
| `GET` | `/.well-known/did.json` | AgentProof's issuer DID document. |

### Authenticated (Ed25519 signature)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agents/{did}/verify-email` | Trigger email verification. Sends 6-digit code via Resend. Requires signature. |
| `POST` | `/agents/{did}/confirm-email` | Submit 6-digit code + signature. Upgrades to L1, re-issues credential. |
| `POST` | `/agents/{did}/revoke` | Revoke credential. Requires signature. |
| `DELETE` | `/agents/{did}` | Delete agent entirely. Requires signature. |

### Auth Model

- **Agent owners** authenticate by signing a payload with their Ed25519 private key. For registration: `SHA-256(public_key_hex + ":" + timestamp_iso)`. For mutations: `SHA-256(did + ":" + action + ":" + timestamp_iso)` where `action` is one of `verify-email`, `confirm-email`, `revoke`, `delete`. Timestamp must be within 5 minutes to prevent replay attacks.
- **Verification is public** — anyone can verify any agent with zero auth. This is the core value proposition.

---

## Registration Flow (L0)

```
CLI                              AgentProof API
 |                                    |
 |  POST /agents/register             |
 |  { public_key, display_name,       |
 |    timestamp, signature }           |
 |──────────────────────────────────►  |
 |                                    |  1. Verify signature over
 |                                    |     SHA-256(pubkey_hex + ":" + timestamp)
 |                                    |  2. Check timestamp within 5 min
 |                                    |  3. Derive did:key from pubkey
 |                                    |  4. Store agent record
 |                                    |  5. Issue L0 credential (JWT)
 |  { did, verification_level: 0,     |
 |    credential_jwt }                 |
 |  ◄──────────────────────────────── |
```

---

## Email Verification Flow (L1)

```
CLI                              AgentProof API           Resend
 |                                    |                     |
 |  POST /agents/{did}/verify-email   |                     |
 |  { timestamp, signature }          |                     |
 |──────────────────────────────────►  |                     |
 |                                    |  Generate 6-digit   |
 |                                    |  code, store hash   |
 |                                    |  (expires 10 min)   |
 |                                    |  ──────────────────►|
 |                                    |  Send code email    |
 |  { message: "code sent" }          |                     |
 |  ◄──────────────────────────────── |                     |
 |                                    |                     |
 |  POST /agents/{did}/confirm-email  |                     |
 |  { code, timestamp, signature }    |                     |
 |──────────────────────────────────►  |                     |
 |                                    |  1. Verify signature |
 |                                    |  2. Verify code hash |
 |                                    |  3. Check not expired|
 |                                    |  4. Set L1           |
 |                                    |  5. Re-issue JWT     |
 |  { verification_level: 1,          |                     |
 |    credential_jwt }                 |                     |
 |  ◄──────────────────────────────── |                     |
```

---

## Credential Format

JWT signed with AgentProof's Ed25519 issuer key:

```json
{
  "iss": "did:web:agentproof.dev",
  "sub": "did:key:z6MkjVXU...",
  "iat": 1714600000,
  "exp": 1722376000,
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "AgentOwnershipCredential"],
    "credentialSubject": {
      "id": "did:key:z6MkjVXU...",
      "verificationLevel": 1,
      "emailVerified": true
    }
  }
}
```

- **TTL:** 90 days. Auto-renewal is post-MVP; agents re-register when expired.
- **Issuer key:** Ed25519 keypair stored as environment variable on Fly.io. Published at `/.well-known/did.json`.
- **DID derivation:** `did:key` — multicodec prefix `0xed01` + raw 32-byte pubkey → base58btc → `did:key:z6Mk...`. Deterministic, no registry needed.

---

## Crypto

| Operation | Library | Algorithm |
|-----------|---------|-----------|
| Keypair generation | PyNaCl | Ed25519 |
| Signing / verification | PyNaCl | Ed25519 |
| DID derivation | Manual (multicodec + base58btc) | did:key spec |
| JWT issuance | PyJWT + PyNaCl | Ed25519-signed JWT |
| Private key encryption (CLI) | PyNaCl SecretBox | XSalsa20-Poly1305 |
| Email code hashing | hashlib | SHA-256 |
| Signature payload | hashlib | SHA-256 |

**Security notes:**
- Signature payloads include a timestamp (5-minute window) to prevent replay attacks.
- Email verification codes expire after 10 minutes.
- Code is stored as SHA-256 hash, not plaintext.
- CLI encrypts private key at rest with user passphrase via PyNaCl SecretBox.

---

## CLI

Install: `pip install agentproof`

### Commands

| Command | Description |
|---------|-------------|
| `agentproof keygen` | Generate Ed25519 keypair, save to `~/.agentproof/` |
| `agentproof register --name "my-agent"` | Register agent with API, save DID + credential |
| `agentproof verify-email --email you@example.com` | Trigger 6-digit code |
| `agentproof confirm-email --code 482910` | Submit code, upgrade to L1 |
| `agentproof verify did:key:z6Mk...` | Public verification lookup |
| `agentproof revoke` | Revoke credential |
| `agentproof credential --format jwt` | Output credential JWT |
| `agentproof credential --format agent-card` | Output A2A Agent Card JSON snippet |

### Local Config

```
~/.agentproof/
├── agent.key          # Ed25519 private key (encrypted, XSalsa20-Poly1305)
├── agent.pub          # Ed25519 public key (hex)
├── credential.jwt     # Current signed credential
└── config.toml        # API base URL, agent DID
```

- **Single agent per install.** Use `--config-dir` for multiple agents.
- **`--api-url` flag** on all commands. Defaults to `https://api.agentproof.dev/v1`.
- **Passphrase prompt** on operations that require the private key.

---

## Open Source Strategy

**Open source (this repo):**
- Core crypto library (Ed25519, DID, credential verification)
- CLI tool
- API client SDK
- Credential verification logic (offline-capable)

**Private (later, if needed):**
- Issuer private key
- Deployment config, secrets, ops
- Email infrastructure specifics

The API server code itself stays open — anyone can self-host. This builds trust and attracts contributors from agent framework communities (LangChain, CrewAI, AutoGen).

---

## Post-MVP Roadmap

**Abuse prevention:**
- Rate limiting by IP on registration and email endpoints
- Request throttling on public verify
- Audit logging

**Security hardening:**
- Issuer key in HSM / cloud KMS (not env var)
- Key rotation support (multiple issuer keys, key ID in JWT header)
- Certificate transparency / audit log
- Credential revocation lists (CRL)

**Features:**
- L2/L3 verification (government ID, ZKP)
- Platform API keys + batch verify
- Web app (landing, register, verify, dashboard)
- Auto-renewal of credentials
- Delegation chains (sub-agents)
- Webhook notifications
- A2A/MCP protocol deep integrations
- OAuth/OIDC integration
- Paid tiers

---

## Success Criteria

- 100 registered agents in the first week after launch
- Full L0 + L1 flow working end-to-end (CLI → API → credential)
- `pip install agentproof` works from PyPI
- Public verify endpoint responds < 200ms
- Deployed and live at `api.agentproof.dev`
