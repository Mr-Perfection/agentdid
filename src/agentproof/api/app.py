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
