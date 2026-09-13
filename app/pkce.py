"""Generation d'une paire PKCE (RFC 7636), methode S256 uniquement."""

from __future__ import annotations

import base64
import hashlib
import secrets


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> tuple[str, str]:
    """Retourne (code_verifier, code_challenge)."""
    code_verifier = _b64url(secrets.token_bytes(64))  # ~86 chars, dans les bornes 43-128
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    return code_verifier, code_challenge
