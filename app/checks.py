"""Controles des bonnes pratiques (recommendations.py) appliques aux tokens obtenus,
affiches sur la page de resultat (ENABLE_RECOMMANDATIONS).

Seuls les points verifiables depuis tokenlab apparaissent ici : la journalisation
des tokens ou le format des Valid Redirect URIs, par exemple, ne se voient pas de
l'exterieur.
"""

from __future__ import annotations

import time

from .config import Settings
from .oidc import ASYMMETRIC_ALGS

OK, WARN, FAIL, INFO, NA = "ok", "warn", "fail", "info", "na"

# Audience ajoutee par defaut par Keycloak (client "account") : ne designe pas une API.
KEYCLOAK_DEFAULT_AUDIENCES = {"account"}


def _check(status: str, label: str, detail: str = "") -> dict:
    return {"status": status, "label": label, "detail": detail}


def _audiences(payload: dict) -> list[str]:
    aud = payload.get("aud")
    if aud is None:
        return []
    return [aud] if isinstance(aud, str) else list(aud)


def _jwt_common_checks(decoded: dict, issuer: str | None, now: float) -> list[dict]:
    header = decoded.get("header") or {}
    payload = decoded.get("payload") or {}
    checks = []

    signature = decoded.get("signature") or {}
    if signature.get("verified"):
        checks.append(_check(OK, "Signature valide (clés du JWKS du realm)"))
    else:
        checks.append(_check(FAIL, "Signature valide (clés du JWKS du realm)", signature.get("error", "")))

    alg = header.get("alg")
    if not alg or str(alg).lower() == "none":
        checks.append(_check(FAIL, "Algorithme de signature", f"alg = {alg!r}"))
    elif alg in ASYMMETRIC_ALGS:
        checks.append(_check(OK, "Algorithme de signature", f"alg = {alg} (asymétrique)"))
    else:
        checks.append(_check(WARN, "Algorithme de signature", f"alg = {alg} (non asymétrique)"))

    embedded = [h for h in ("jku", "x5u", "jwk") if h in header]
    if embedded:
        checks.append(
            _check(
                WARN,
                "Clés prises uniquement depuis le jwks_uri du realm",
                f"en-tête(s) {', '.join(embedded)} présent(s) dans le token : à ignorer côté client/API",
            )
        )
    else:
        checks.append(
            _check(OK, "Clés prises uniquement depuis le jwks_uri du realm", "aucun en-tête jku/x5u/jwk")
        )

    iss = payload.get("iss")
    if issuer and iss == issuer:
        checks.append(_check(OK, "iss = URL du realm", iss))
    else:
        checks.append(_check(FAIL, "iss = URL du realm", f"iss = {iss!r}, attendu {issuer!r}"))

    exp = payload.get("exp")
    if not isinstance(exp, int | float):
        checks.append(_check(FAIL, "exp non dépassé", "claim exp absent"))
    elif exp > now:
        checks.append(_check(OK, "exp non dépassé", f"expire dans {int(exp - now)} s"))
    else:
        checks.append(_check(FAIL, "exp non dépassé", f"expiré depuis {int(now - exp)} s"))

    return checks


def _id_token_checks(
    decoded: dict | None, settings: Settings, issuer: str | None, nonce: str | None, acr_info: dict | None
) -> list[dict]:
    if not decoded:
        return [_check(FAIL, "ID token présent", "aucun id_token dans la réponse du token endpoint")]
    if "error" in decoded:
        return [_check(FAIL, "ID token décodable", decoded["error"])]

    now = time.time()
    payload = decoded.get("payload") or {}
    client_id = settings.keycloak_client_id
    checks = _jwt_common_checks(decoded, issuer, now)

    auds = _audiences(payload)
    if client_id in auds:
        checks.append(_check(OK, "aud contient le client_id", f"aud = {auds}"))
    else:
        checks.append(_check(FAIL, "aud contient le client_id", f"aud = {auds}, attendu {client_id!r}"))

    azp = payload.get("azp")
    if azp is not None:
        status = OK if azp == client_id else FAIL
        checks.append(_check(status, "azp = client_id", f"azp = {azp!r}"))
    elif len(auds) > 1:
        checks.append(
            _check(FAIL, "azp = client_id", "azp absent alors que aud contient plusieurs audiences")
        )
    else:
        checks.append(_check(NA, "azp = client_id", "azp absent (audience unique)"))

    received_nonce = payload.get("nonce")
    if not nonce:
        checks.append(_check(NA, "nonce = valeur envoyée", "aucun nonce envoyé"))
    elif received_nonce == nonce:
        checks.append(_check(OK, "nonce = valeur envoyée"))
    elif received_nonce is None:
        checks.append(_check(FAIL, "nonce = valeur envoyée", "nonce absent de l'id_token"))
    else:
        checks.append(_check(FAIL, "nonce = valeur envoyée", f"nonce reçu {received_nonce!r} différent"))

    if acr_info:
        received = acr_info.get("received")
        detail = f"demandé : {acr_info['requested']} — reçu : {received!r}"
        if acr_info.get("match"):
            checks.append(_check(OK, "acr conforme à la demande", detail))
        else:
            # Hint simple (acr_values) : Keycloak peut legitimement l'ignorer.
            status = FAIL if acr_info.get("essential") else WARN
            checks.append(_check(status, "acr conforme à la demande", detail))

    return checks


def _access_token_checks(
    decoded: dict | None, settings: Settings, issuer: str | None, dpop_info: dict | None
) -> list[dict]:
    if not decoded:
        return [_check(FAIL, "Access token présent", "aucun access_token dans la réponse")]
    if "error" in decoded:
        return [
            _check(
                INFO,
                "Access token JWT",
                "token opaque (non JWT) : l'API doit le valider par introspection",
            )
        ]

    now = time.time()
    payload = decoded.get("payload") or {}
    checks = _jwt_common_checks(decoded, issuer, now)

    auds = _audiences(payload)
    api_auds = [a for a in auds if a not in KEYCLOAK_DEFAULT_AUDIENCES]
    if api_auds:
        checks.append(
            _check(
                OK,
                "aud contient l'identifiant d'une API",
                f"aud = {auds} — chaque API doit vérifier que son identifiant y figure",
            )
        )
    else:
        checks.append(
            _check(
                WARN,
                "aud contient l'identifiant d'une API",
                f"aud = {auds or 'absent'} : aucune audience d'API, ajouter un audience mapper au client",
            )
        )

    # Keycloak positionne typ = "DPoP" sur un access token lie par DPoP (claim cnf).
    typ = payload.get("typ")
    expected_typ = "DPoP" if "cnf" in payload else "Bearer"
    if typ == expected_typ:
        checks.append(_check(OK, "typ distingue l'access token d'un ID token", f"typ = {typ}"))
    else:
        checks.append(
            _check(
                FAIL if typ == "ID" else WARN,
                "typ distingue l'access token d'un ID token",
                f"typ = {typ!r}, attendu {expected_typ!r}",
            )
        )

    scope = payload.get("scope")
    roles = (payload.get("realm_access") or {}).get("roles") or []
    clients = sorted((payload.get("resource_access") or {}).keys())
    detail = f"scope = {scope!r} — rôles realm : {roles or 'aucun'}"
    if clients:
        detail += f" — rôles client pour : {clients}"
    checks.append(_check(INFO, "Scopes / rôles à vérifier par l'API pour chaque opération", detail))

    if "cnf" in payload:
        checks.append(
            _check(
                INFO,
                "Token lié (claim cnf)",
                "l'API doit vérifier la preuve DPoP à chaque appel, ou rejeter ce token",
            )
        )
    elif dpop_info is None:
        checks.append(_check(NA, "Token lié (claim cnf)", "token bearer classique, sans cnf"))

    return checks


def _general_checks(settings: Settings, dpop_info: dict | None) -> list[dict]:
    checks = []
    confidential = bool(settings.keycloak_client_secret)

    if settings.enable_pkce:
        checks.append(_check(OK, "PKCE S256", "code_challenge_method = S256"))
    elif confidential:
        checks.append(_check(WARN, "PKCE S256", "désactivé (recommandé pour un client confidentiel)"))
    else:
        checks.append(_check(FAIL, "PKCE S256", "désactivé alors que le client est public"))

    if dpop_info is None:
        checks.append(_check(WARN, "Tokens liés par DPoP", "DPoP désactivé : un token volé est rejouable"))
    elif dpop_info.get("match"):
        checks.append(_check(OK, "Tokens liés par DPoP", "cnf.jkt = empreinte de la clé DPoP"))
    elif dpop_info.get("cnf_jkt"):
        checks.append(_check(FAIL, "Tokens liés par DPoP", "cnf.jkt ne correspond pas à la clé DPoP"))
    else:
        checks.append(
            _check(
                FAIL,
                "Tokens liés par DPoP",
                "cnf absent : activer 'OAuth 2.0 DPoP Bound Access Tokens' sur le client",
            )
        )

    checks.append(_check(OK, "state envoyé et vérifié au retour", "tentative retrouvée à partir du state"))
    return checks


def run_checks(
    settings: Settings,
    discovery: dict,
    decoded: dict,
    *,
    nonce: str | None,
    dpop_info: dict | None,
    acr_info: dict | None,
) -> dict:
    issuer = discovery.get("issuer")
    groups = [
        {"title": "Général", "checks": _general_checks(settings, dpop_info)},
        {
            "title": "ID token (côté application)",
            "checks": _id_token_checks(decoded.get("id_token"), settings, issuer, nonce, acr_info),
        },
        {
            "title": "Access token (côté API)",
            "checks": _access_token_checks(decoded.get("access_token"), settings, issuer, dpop_info),
        },
    ]
    counts: dict[str, int] = {status: 0 for status in (OK, WARN, FAIL, INFO, NA)}
    for group in groups:
        for check in group["checks"]:
            counts[check["status"]] += 1
    return {"groups": groups, "counts": counts}
