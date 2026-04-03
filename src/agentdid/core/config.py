from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://localhost:5432/agentdid"
    issuer_private_key_hex: str = ""
    issuer_did: str = "did:web:rureal.ai"
    credential_ttl_days: int = 90
    timestamp_tolerance_seconds: int = 300
    resend_api_key: str = ""
    resend_from_email: str = "verify@rureal.ai"
    api_base_url: str = "https://agentdid-api.fly.dev/v1"

    model_config = {"env_prefix": "AGENTDID_"}


settings = Settings()
