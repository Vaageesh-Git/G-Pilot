FROM python:3.12-slim@sha256:520153e2deb359602c9cffd84e491e3431d76e7bf95a3255c9ce9433b76ab99a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY backend/pyproject.toml /app/backend/pyproject.toml
COPY backend/vuln_swarm /app/backend/vuln_swarm
COPY README.md /app/README.md

RUN pip install --no-cache-dir /app/backend

USER appuser

EXPOSE 8000

CMD ["uvicorn", "vuln_swarm.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
