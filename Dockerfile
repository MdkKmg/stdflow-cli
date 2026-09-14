FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Binaire uv officiel (image distroless dediee), pas d'installation via pip necessaire.
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /uvx /usr/local/bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Couche dependances seule, pour beneficier du cache Docker tant que pyproject/uv.lock ne changent pas.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app

RUN addgroup --system --gid 10001 stdflow \
   && adduser --system --uid 10001 --ingroup stdflow stdflow \
   && chown -R stdflow:stdflow /app
USER 10001

EXPOSE 8080

CMD ["/app/.venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
