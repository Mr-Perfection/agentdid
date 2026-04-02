FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
COPY README.md .

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "agentproof.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
