# agentdid

Cryptographic identity for AI agents. Prove a human stands behind the bot.

[![PyPI version](https://img.shields.io/pypi/v/agentdid)](https://pypi.org/project/agentdid/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/Mr-Perfection/agentdid/ci.yml?label=tests)](https://github.com/Mr-Perfection/agentdid/actions)

---

## The problem

AI agents are proliferating across the web, but there is no standard way to verify who built or controls them. Without cryptographic identity, agents can impersonate, spam, and erode trust in every system they touch. agentdid gives each agent a verifiable identity backed by Ed25519 signatures and W3C Decentralized Identifiers.

## How it works

agentdid generates an Ed25519 keypair for your agent, registers it as a `did:key` identifier with the agentdid registry, and issues a verifiable credential as a compact JWT. Anyone can resolve the DID and verify the credential without contacting the agent's owner. Optional email verification raises the trust level from L0 (registered) to L1 (email verified).

## Quick-start

Get a verifiable agent identity in under two minutes.

```bash
# Install
pip install agentdid

# Generate a keypair (saved to ~/.agentdid/)
agentdid keygen

# Register your agent
agentdid register --name "my-agent" --email "you@example.com"

# Verify any agent by DID
agentdid verify did:key:z6Mkr...
```

After registration, `~/.agentdid/` contains your private key and credential JWT.

## CLI reference

| Command | Description |
| --- | --- |
| `agentdid keygen` | Generate a new Ed25519 keypair |
| `agentdid register` | Register your agent (`--name`, `--email`) |
| `agentdid verify <did>` | Verify an agent by DID |
| `agentdid verify-email` | Send email verification for your agent |
| `agentdid confirm-email` | Confirm email with verification code |
| `agentdid revoke` | Revoke your agent's credential |
| `agentdid credential jwt` | Display your agent's credential JWT |
| `agentdid credential agent-card` | Generate an agent card with embedded proof |

**Global options:**

- `--config-dir PATH` -- Override config directory (default: `~/.agentdid`)
- `--api-url URL` -- Override API base URL (default: `https://agentdid-api.fly.dev/v1`)

## API reference

Base URL: `https://agentdid-api.fly.dev`

| Method | Path | Description | Auth |
| --- | --- | --- | --- |
| POST | `/v1/agents/register` | Register a new agent | Signed request |
| GET | `/v1/agents/{did}/verify` | Verify an agent | Public |
| GET | `/v1/agents/{did}/credential` | Get agent's credential JWT | Public |
| POST | `/v1/agents/{did}/verify-email` | Send email verification | Signed request |
| POST | `/v1/agents/{did}/confirm-email` | Confirm email code | Signed request |
| POST | `/v1/agents/{did}/revoke` | Revoke agent credential | Signed request |
| DELETE | `/v1/agents/{did}` | Delete agent registration | Signed request |
| GET | `/.well-known/did.json` | Issuer DID document | Public |

"Signed request" means the request body includes an Ed25519 signature from the agent's private key, verified server-side against the registered DID.

## Architecture

- **DID method:** `did:key` (Ed25519) for agents, `did:web` for the issuer
- **Credentials:** JWT format only -- no JSON-LD complexity
- **Signatures:** Ed25519 for all cryptographic operations
- **Verification levels:** L0 (registered), L1 (email verified)

The issuer's DID document is served at `/.well-known/did.json` so any party can independently verify credentials without trusting a third-party resolver.

## Development

```bash
git clone https://github.com/Mr-Perfection/agentdid.git
cd agentproof
pip install -e ".[dev]"
pytest
```

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[Apache 2.0](LICENSE)
