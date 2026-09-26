"""Liste de bonnes pratiques minimales pour les clients OIDC Keycloak, affichee sur
la page d'accueil (ENABLE_RECOMMANDATIONS).

Les points verifiables depuis tokenlab sont controles sur les tokens obtenus par
`checks.py` et affiches sur la page de resultat.
"""

from __future__ import annotations

from markupsafe import Markup

RFC9700 = "https://www.rfc-editor.org/rfc/rfc9700"
RFC9449 = "https://www.rfc-editor.org/rfc/rfc9449"
RFC8725 = "https://www.rfc-editor.org/rfc/rfc8725"
OIDC_CORE = "https://openid.net/specs/openid-connect-core-1_0.html"
ANSSI = (
    "https://cyber.gouv.fr/publications/"
    "recommandations-pour-la-securisation-de-la-mise-en-oeuvre-du-protocole-openid-connect"
)


def _src(label: str, url: str) -> dict:
    return {"label": label, "url": url}


def _item(text: str, *sources: dict) -> dict:
    return {"text": Markup(text), "sources": list(sources)}  # noqa: S704 - contenu statique de ce module


RECOMMENDATIONS: list[dict] = [
    {
        "title": "Général",
        "groups": [
            {
                "items": [
                    _item(
                        "PKCE (<code>S256</code>) <strong>obligatoire</strong> pour les clients publics, "
                        "<strong>recommandé</strong> pour les clients confidentiels",
                        _src("RFC 9700 §2.1.1", f"{RFC9700}#section-2.1.1"),
                    ),
                    _item(
                        "DPoP comme <strong>objectif</strong> de liaison des tokens",
                        _src("RFC 9700 §2.2", f"{RFC9700}#section-2.2"),
                        _src("RFC 9449", RFC9449),
                    ),
                    _item(
                        "<em>Valid Redirect URIs</em> déclarées de façon <strong>exacte</strong>, "
                        "sans joker (<code>*</code>)",
                        _src("RFC 9700 §2.1", f"{RFC9700}#section-2.1"),
                    ),
                    _item(
                        "Ne jamais journaliser les tokens (access, refresh, ID token)",
                        _src("ANSSI R32", ANSSI),
                    ),
                ]
            }
        ],
    },
    {
        "title": "RP — Application qui authentifie l'utilisateur",
        "groups": [
            {
                "items": [
                    _item(
                        "<code>state</code> envoyé dans la requête d'authentification et vérifié au retour",
                        _src("ANSSI R10, R22", ANSSI),
                    ),
                    _item(
                        "Ne jamais envoyer l'ID token à une API : seul l'access token sert à appeler "
                        "une ressource",
                    ),
                ]
            },
            {
                "title": "Validation de l'ID token",
                "sources": [
                    _src("OIDC Core §3.1.3.7", f"{OIDC_CORE}#IDTokenValidation"),
                    _src("ANSSI R28", ANSSI),
                ],
                "items": [
                    _item(
                        "Signature valide, avec les clés du <code>jwks_uri</code> du realm configuré "
                        "uniquement — ignorer les en-têtes <code>jku</code>, <code>x5u</code>, "
                        "<code>jwk</code> du token",
                    ),
                    _item(
                        "Algorithme de signature fixé en configuration, jamais <code>none</code>",
                        _src("ANSSI R44", ANSSI),
                        _src("RFC 8725 §3.1", f"{RFC8725}#section-3.1"),
                    ),
                    _item("<code>iss</code> = URL du realm"),
                    _item("<code>aud</code> contient le <code>client_id</code>"),
                    _item("<code>azp</code> = <code>client_id</code>"),
                    _item(
                        "<code>nonce</code> = valeur envoyée dans la requête d'authentification",
                        _src("ANSSI R14", ANSSI),
                    ),
                    _item("<code>exp</code> non dépassé"),
                    _item(
                        "<code>acr</code> conforme à une des valeurs demandées, si <code>acr_values</code> "
                        "est utilisé",
                    ),
                ],
            },
        ],
    },
    {
        "title": "RS — API qui reçoit l'access token",
        "groups": [
            {
                "items": [
                    _item(
                        "Signature valide, avec les clés du <code>jwks_uri</code> du realm configuré "
                        "uniquement — ignorer les en-têtes <code>jku</code>, <code>x5u</code>, "
                        "<code>jwk</code> du token",
                    ),
                    _item(
                        "Algorithme de signature fixé en configuration, jamais <code>none</code>",
                        _src("ANSSI R44", ANSSI),
                        _src("RFC 8725 §3.1", f"{RFC8725}#section-3.1"),
                    ),
                    _item("<code>iss</code> = URL du realm"),
                    _item("<code>exp</code> non dépassé"),
                    _item(
                        "<code>aud</code> contient l'identifiant de l'API — demander un "
                        "<strong>audience mapper</strong> à la création du client",
                        _src("RFC 9700 §2.3", f"{RFC9700}#section-2.3"),
                    ),
                    _item(
                        "Rejeter les ID tokens : claim Keycloak <code>typ</code> = <code>Bearer</code>, "
                        "ou <code>DPoP</code> pour un token lié (un ID token porte <code>typ</code> = "
                        "<code>ID</code>)",
                    ),
                    _item(
                        "Vérifier les scopes / rôles requis pour chaque opération : un token valide "
                        "n'autorise pas tout",
                        _src("RFC 9700 §2.3", f"{RFC9700}#section-2.3"),
                    ),
                    _item(
                        "DPoP : vérifier la preuve DPoP, <strong>ou</strong> rejeter tout token portant "
                        "un claim <code>cnf</code>",
                        _src("RFC 9449", RFC9449),
                    ),
                ]
            }
        ],
    },
]

REFERENCES: list[dict] = [
    _src("RFC 9700 — OAuth 2.0 Security Best Current Practice (janvier 2025)", RFC9700),
    _src("RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)", RFC9449),
    _src("RFC 8725 — JSON Web Token Best Current Practices", RFC8725),
    _src("OpenID Connect Core 1.0", OIDC_CORE),
    _src(
        "ANSSI-PA-080 — Recommandations pour la sécurisation de la mise en œuvre du protocole "
        "OpenID Connect (v1.0, 2020)",
        ANSSI,
    ),
]

RECOMMENDATIONS_COUNT: int = sum(len(g["items"]) for s in RECOMMENDATIONS for g in s["groups"])
