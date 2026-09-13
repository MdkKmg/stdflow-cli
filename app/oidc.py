"""Logique du standard flow (authorization code) OIDC face a Keycloak.

Toutes les fonctions ici prennent un `transcript` (liste) + un logger, et y
enregistrent chaque appel HTTP via `httplog.record_exchange`.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any

import httpx
from jose import jwt as jose_jwt

from .config import Settings
from .dpop import create_dpop_proof, is_use_dpop_nonce_error
from .httplog import record_exchange


async def fetch_discovery(client: httpx.AsyncClient, settings: Settings, transcript: list, logger: logging.Logger) -> dict:
    url = settings.discovery_url
    response = await client.get(url)
    record_exchange(
        transcript, logger,
        step="1. Discovery OIDC (.well-known)",
        method="GET", url=url,
        response=response,
    )
    response.raise_for_status()
    return response.json()


def build_authorization_url(
    settings: Settings,
    discovery: dict,
    state: str,
    code_challenge: str | None,
    acr_values: str | None = None,
    acr_essential: bool = False,
) -> tuple[str, dict]:
    params = {
        "response_type": "code",
        "client_id": settings.keycloak_client_id,
        "redirect_uri": settings.redirect_uri,
        "scope": settings.keycloak_scope,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    if acr_values:
        # "hint" standard, que Keycloak peut prendre en compte sans le forcer.
        params["acr_values"] = acr_values
        if acr_essential:
            # exigence stricte via le parametre OIDC `claims` : Keycloak doit
            # echouer l'authentification s'il ne peut pas satisfaire une de ces valeurs.
            params["claims"] = json.dumps(
                {"id_token": {"acr": {"essential": True, "values": acr_values.split()}}},
                separators=(",", ":"),
            )
    url = f"{discovery['authorization_endpoint']}?{urllib.parse.urlencode(params)}"
    return url, params


def build_logout_url(settings: Settings, discovery: dict, id_token: str | None) -> str | None:
    """URL de RP-Initiated Logout (OIDC) : ferme la session cote Keycloak, pas
    seulement cote client. Necessite que `PUBLIC_BASE_URL/` soit dans les
    'Valid post logout redirect URIs' du client Keycloak."""
    end_session_endpoint = discovery.get("end_session_endpoint")
    if not end_session_endpoint:
        return None
    params = {
        "client_id": settings.keycloak_client_id,
        "post_logout_redirect_uri": f"{settings.public_base_url}/",
    }
    if id_token:
        # evite la page de confirmation "voulez-vous vraiment vous deconnecter ?"
        # et cible precisement la session associee a ce token.
        params["id_token_hint"] = id_token
    return f"{end_session_endpoint}?{urllib.parse.urlencode(params)}"


async def exchange_code_for_tokens(
    client: httpx.AsyncClient,
    settings: Settings,
    discovery: dict,
    *,
    code: str,
    code_verifier: str | None,
    dpop_jwk: dict | None,
    transcript: list,
    logger: logging.Logger,
) -> tuple[dict | None, httpx.Response]:
    token_endpoint = discovery["token_endpoint"]
    data: dict[str, Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "client_id": settings.keycloak_client_id,
    }
    if settings.keycloak_client_secret:
        data["client_secret"] = settings.keycloak_client_secret
    if code_verifier:
        data["code_verifier"] = code_verifier

    headers: dict[str, str] = {}
    step_suffix = ""
    if dpop_jwk:
        headers["DPoP"] = create_dpop_proof(dpop_jwk, htm="POST", htu=token_endpoint)

    response = await client.post(token_endpoint, data=data, headers=headers)
    record_exchange(
        transcript, logger,
        step=f"3. Echange du code contre des tokens{step_suffix}",
        method="POST", url=token_endpoint,
        request_headers=headers, request_body=data,
        response=response,
    )

    if dpop_jwk and response.status_code in (400, 401):
        body = _safe_json(response)
        if is_use_dpop_nonce_error(response.status_code, body):
            nonce = response.headers.get("DPoP-Nonce")
            headers["DPoP"] = create_dpop_proof(dpop_jwk, htm="POST", htu=token_endpoint, nonce=nonce)
            response = await client.post(token_endpoint, data=data, headers=headers)
            record_exchange(
                transcript, logger,
                step="3b. Echange du code, retry avec DPoP-Nonce",
                method="POST", url=token_endpoint,
                request_headers=headers, request_body=data,
                response=response,
            )

    if response.status_code != 200:
        return None, response
    return response.json(), response


async def call_userinfo(
    client: httpx.AsyncClient,
    discovery: dict,
    *,
    access_token: str,
    token_type: str,
    dpop_jwk: dict | None,
    transcript: list,
    logger: logging.Logger,
) -> dict | None:
    userinfo_endpoint = discovery.get("userinfo_endpoint")
    if not userinfo_endpoint:
        return None

    scheme = "DPoP" if dpop_jwk else token_type or "Bearer"
    headers = {"Authorization": f"{scheme} {access_token}"}
    if dpop_jwk:
        headers["DPoP"] = create_dpop_proof(
            dpop_jwk, htm="GET", htu=userinfo_endpoint, access_token=access_token,
        )

    response = await client.get(userinfo_endpoint, headers=headers)
    record_exchange(
        transcript, logger,
        step="4. Appel userinfo avec l'access_token obtenu",
        method="GET", url=userinfo_endpoint,
        request_headers=headers,
        response=response,
    )

    if dpop_jwk and response.status_code in (400, 401):
        body = _safe_json(response)
        if is_use_dpop_nonce_error(response.status_code, body):
            nonce = response.headers.get("DPoP-Nonce")
            headers["DPoP"] = create_dpop_proof(
                dpop_jwk, htm="GET", htu=userinfo_endpoint, nonce=nonce, access_token=access_token,
            )
            response = await client.get(userinfo_endpoint, headers=headers)
            record_exchange(
                transcript, logger,
                step="4b. Appel userinfo, retry avec DPoP-Nonce",
                method="GET", url=userinfo_endpoint,
                request_headers=headers,
                response=response,
            )

    if response.status_code != 200:
        return None
    return response.json()


def decode_jwt_unverified(token: str) -> dict:
    """Decode un JWT sans verifier la signature (outil de debug, pas de validation)."""
    return {
        "header": jose_jwt.get_unverified_header(token),
        "payload": jose_jwt.get_unverified_claims(token),
    }


def _safe_json(response: httpx.Response) -> dict | None:
    try:
        return response.json()
    except ValueError:
        return None
