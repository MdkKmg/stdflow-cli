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

# Verification TLS des appels HTTP vers Keycloak, figee au build de l'image (et non au
# deploiement) : passer a "false" ici uniquement pour une image de dev face a un
# certificat auto-signe, jamais en dehors de ce cas. Non surchargeable via .env/ConfigMap.
ENV HTTP_VERIFY_TLS=true

WORKDIR /app

# Couche dependances seule, pour beneficier du cache Docker tant que pyproject/uv.lock ne changent pas.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app

RUN addgroup --system --gid 10001 tokenlab \
   && adduser --system --uid 10001 --ingroup tokenlab tokenlab \
   && chown -R tokenlab:tokenlab /app
USER 10001

EXPOSE 8080

CMD ["/app/.venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
