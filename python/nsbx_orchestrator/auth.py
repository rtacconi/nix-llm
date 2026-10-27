"""Bearer tokens → principals. Tokens are stored as SHA-256 digests."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str
    profiles: frozenset[str]


class TokenAuth:
    def __init__(self, entries: dict[str, Principal]) -> None:
        """``entries`` maps hex SHA-256 of a token to its principal."""
        self._entries = {bytes.fromhex(k): v for k, v in entries.items()}

    @staticmethod
    def digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def authenticate(self, authorization: str | None) -> Principal | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        presented = hashlib.sha256(authorization[len("Bearer ") :].encode()).digest()
        found: Principal | None = None
        # Compare against every entry so timing does not depend on which matched.
        for digest, principal in self._entries.items():
            if hmac.compare_digest(digest, presented):
                found = principal
        return found
