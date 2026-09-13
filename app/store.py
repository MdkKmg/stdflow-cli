"""Store en memoire des tentatives de login en cours (state -> contexte du flow).

Volontairement simple (dict + TTL) : stdflow-cli est un outil de test destine a
tourner en un seul replica. Voir README pour cette limitation.
"""

from __future__ import annotations

import time
from threading import Lock
from typing import Any


class StateStore:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._data: dict[str, dict[str, Any]] = {}
        self._lock = Lock()

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [k for k, v in self._data.items() if now - v["_created"] > self._ttl]
        for k in expired:
            self._data.pop(k, None)

    def set(self, state: str, entry: dict[str, Any]) -> None:
        with self._lock:
            self._purge_expired()
            entry["_created"] = time.time()
            self._data[state] = entry

    def pop(self, state: str) -> dict[str, Any] | None:
        with self._lock:
            self._purge_expired()
            return self._data.pop(state, None)
