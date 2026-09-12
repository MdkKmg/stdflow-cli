from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import get_settings
from .dpop import generate_dpop_jwk
from .httplog import configure_logging
from .oidc import (
    build_authorization_url,
    call_userinfo,
    decode_jwt_unverified,
    exchange_code_for_tokens,
    fetch_discovery,
)
from .pkce import generate_pkce_pair
from .store import StateStore

BASE_DIR = Path(__file__).parent

settings = get_settings()
logger = configure_logging(settings.log_level)
store = StateStore(ttl_seconds=settings.state_ttl_seconds)

app = FastAPI(title="stdflow-cli")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.filters["pretty_json"] = lambda obj: json.dumps(obj, indent=2, ensure_ascii=False, default=str)
if (BASE_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "config": settings.redacted()}
    )


def _render_error(request: Request, error: str, error_description: str, status_code: int = 502):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "error": error, "error_description": error_description},
        status_code=status_code,
    )


@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(24)
    transcript: list[dict] = []

    entry: dict = {"transcript": transcript}

    code_verifier = code_challenge = None
    if settings.enable_pkce:
        code_verifier, code_challenge = generate_pkce_pair()
        entry["code_verifier"] = code_verifier

    dpop_jwk = None
    if settings.enable_dpop:
        dpop_jwk = generate_dpop_jwk()
        entry["dpop_jwk"] = dpop_jwk

    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            discovery = await fetch_discovery(client, settings, transcript, logger)
    except httpx.HTTPError as exc:
        logger.error('{"event": "discovery_failed", "error": %s}' % json.dumps(str(exc)))
        return _render_error(
            request,
            "discovery_oidc_echouee",
            f"Impossible de recuperer {settings.discovery_url} : {exc}",
        )

    entry["discovery"] = discovery
    store.set(state, entry)

    auth_url = build_authorization_url(settings, discovery, state, code_challenge)
    logger.info(
        '{"event": "authorization_redirect", "url": "%s", "pkce": %s, "dpop": %s}'
        % (auth_url, str(bool(code_challenge)).lower(), str(bool(dpop_jwk)).lower())
    )
    return RedirectResponse(auth_url, status_code=302)


@app.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None,
                    error: str | None = None, error_description: str | None = None):
    entry = store.pop(state) if state else None

    if error or entry is None:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": error or "state_invalide_ou_expire",
                "error_description": error_description
                or "Le parametre 'state' est manquant, inconnu ou a expire (tentative de login trop ancienne ou deja utilisee).",
            },
            status_code=400,
        )

    transcript: list[dict] = entry["transcript"]
    discovery = entry["discovery"]
    code_verifier = entry.get("code_verifier")
    dpop_jwk = entry.get("dpop_jwk")

    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            tokens, token_response = await exchange_code_for_tokens(
                client, settings, discovery,
                code=code, code_verifier=code_verifier, dpop_jwk=dpop_jwk,
                transcript=transcript, logger=logger,
            )

            if tokens is None:
                return templates.TemplateResponse(
                    "result.html",
                    {
                        "request": request,
                        "config": settings.redacted(),
                        "transcript": transcript,
                        "success": False,
                        "token_error_status": token_response.status_code,
                    },
                    status_code=200,
                )

            userinfo = await call_userinfo(
                client, discovery,
                access_token=tokens["access_token"],
                token_type=tokens.get("token_type", "Bearer"),
                dpop_jwk=dpop_jwk,
                transcript=transcript, logger=logger,
            )
    except httpx.HTTPError as exc:
        logger.error('{"event": "token_exchange_failed", "error": %s}' % json.dumps(str(exc)))
        return _render_error(
            request,
            "appel_http_echoue",
            f"Une requete HTTP du flow a echoue : {exc}",
        )

    decoded = {}
    for key in ("access_token", "id_token", "refresh_token"):
        if tokens.get(key):
            try:
                decoded[key] = decode_jwt_unverified(tokens[key])
            except Exception as exc:  # noqa: BLE001 - token peut etre opaque (non-JWT)
                decoded[key] = {"error": f"Non decodable en JWT ({exc})"}

    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "config": settings.redacted(),
            "transcript": transcript,
            "success": True,
            "tokens": tokens,
            "decoded": decoded,
            "userinfo": userinfo,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    )
