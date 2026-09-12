"""Support DPoP (RFC 9449) : cle EC ephemere par tentative de login + preuves JWT signees.

Chaque tentative de standard flow genere sa propre paire de cles P-256, utilisee pour
signer une preuve DPoP a chaque appel HTTP qui le necessite (token endpoint, userinfo).
Gere le cas ou Keycloak exige un nonce serveur (erreur `use_dpop_nonce` + header
`DPoP-Nonce`) : voir `dpop_retry_needed`.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt as jose_jwt


def _int_to_b64url(value: int, length: int = 32) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def generate_dpop_jwk() -> dict:
    """Genere une paire de cles EC P-256 et retourne le JWK prive (avec `d`)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(public_numbers.x),
        "y": _int_to_b64url(public_numbers.y),
        "d": _int_to_b64url(numbers.private_value),
    }


def public_jwk(private_jwk: dict) -> dict:
    return {k: v for k, v in private_jwk.items() if k != "d"}


def create_dpop_proof(
    private_jwk: dict,
    htm: str,
    htu: str,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    """Construit une preuve DPoP (JWT typ=dpop+jwt, alg=ES256) pour une requete HTTP donnee."""
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(private_jwk)}
    claims = {
        "jti": str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
    }
    if nonce:
        claims["nonce"] = nonce
    if access_token:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        claims["ath"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return jose_jwt.encode(claims, private_jwk, algorithm="ES256", headers=header)


def is_use_dpop_nonce_error(status_code: int, body: dict | str | None) -> bool:
    if status_code not in (400, 401):
        return False
    if isinstance(body, dict):
        return body.get("error") == "use_dpop_nonce"
    return False
