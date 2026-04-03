from contextlib import asynccontextmanager
from fastapi import FastAPI
from nacl.signing import SigningKey
from agentdid.api.routes.register import router as register_router
from agentdid.api.routes.verify import router as verify_router
from agentdid.api.routes.credential import router as credential_router
from agentdid.api.routes.email import router as email_router
from agentdid.api.routes.manage import router as manage_router
from agentdid.api.routes.well_known import router as well_known_router
from agentdid.core.config import Settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not hasattr(app.state, "issuer_private_key") or not app.state.issuer_private_key:
        s = Settings()
        if s.issuer_private_key_hex:
            private_key = bytes.fromhex(s.issuer_private_key_hex)
            signing_key = SigningKey(private_key)
            app.state.issuer_private_key = private_key
            app.state.issuer_public_key = bytes(signing_key.verify_key)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="agentdid",
        description="Cryptographic proof that a human stands behind an AI agent.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    app.include_router(well_known_router)  # NO prefix - root level
    app.include_router(register_router, prefix="/v1")
    app.include_router(verify_router, prefix="/v1")
    app.include_router(credential_router, prefix="/v1")
    app.include_router(email_router, prefix="/v1")
    app.include_router(manage_router, prefix="/v1")
    return app


app = create_app()
