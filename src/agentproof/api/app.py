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
