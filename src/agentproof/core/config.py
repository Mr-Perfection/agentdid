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
