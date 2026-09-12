"""Configuration de stdflow-cli, entierement pilotee par variables d'environnement.

Aucune valeur sensible ou fonctionnelle n'est modifiable depuis l'UI : tout se passe
au deploiement (env vars / ConfigMap / Secret kube). L'UI se contente d'afficher la
configuration effective (avec le client secret masque) et de declencher le flow.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Connexion a Keycloak ---
    keycloak_base_url: str = Field(..., description="Ex: https://keycloak.example.com")
    keycloak_realm: str = Field(..., description="Nom du realm Keycloak")
    keycloak_client_id: str = Field(..., description="Client ID (type standard flow)")
    keycloak_client_secret: str | None = Field(default=None, description="Secret si client confidentiel")

    # --- Parametres du flow ---
    keycloak_scope: str = Field(default="openid", description="Scopes demandes, separes par des espaces")
    enable_pkce: bool = Field(default=True, description="Active PKCE (S256) sur le standard flow")
    enable_dpop: bool = Field(default=False, description="Active DPoP (RFC 9449) pour le token endpoint et userinfo")

    # --- Adressage public de l'app (pour construire le redirect_uri) ---
    public_base_url: str = Field(..., description="URL publique de ce service, ex: https://stdflow.mon-cluster.dev")
    redirect_uri: str | None = Field(default=None, description="Override explicite du redirect_uri, sinon derive de public_base_url")

    # --- Divers ---
    port: int = Field(default=8080)
    log_level: str = Field(default="INFO")
    state_ttl_seconds: int = Field(default=300, description="Duree de vie max d'une tentative de login en cours")
    http_timeout_seconds: float = Field(default=10.0)

    @field_validator("keycloak_base_url", "public_base_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("keycloak_scope")
    @classmethod
    def _ensure_openid_scope(cls, v: str) -> str:
        scopes = v.split()
        if "openid" not in scopes:
            scopes.insert(0, "openid")
        return " ".join(scopes)

    @model_validator(mode="after")
    def _derive_redirect_uri(self) -> "Settings":
        if not self.redirect_uri:
            self.redirect_uri = f"{self.public_base_url}/callback"
        return self

    @property
    def discovery_url(self) -> str:
        return f"{self.keycloak_base_url}/realms/{self.keycloak_realm}/.well-known/openid-configuration"

    def redacted(self) -> dict:
        """Vue de la config sure a afficher dans l'UI / les logs."""
        return {
            "keycloak_base_url": self.keycloak_base_url,
            "keycloak_realm": self.keycloak_realm,
            "keycloak_client_id": self.keycloak_client_id,
            "keycloak_client_secret": "***redacted***" if self.keycloak_client_secret else None,
            "client_type": "confidential" if self.keycloak_client_secret else "public",
            "keycloak_scope": self.keycloak_scope,
            "enable_pkce": self.enable_pkce,
            "enable_dpop": self.enable_dpop,
            "redirect_uri": self.redirect_uri,
            "discovery_url": self.discovery_url,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
