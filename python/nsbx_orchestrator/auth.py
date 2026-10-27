"""Bearer tokens → principals. Tokens are stored as SHA-256 digests."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class Principal:
    """A caller and the most it may ever be granted (the principal layer of
    ``effective ⊆ request ⊆ principal ⊆ profile``)."""

    id: str
    profiles: frozenset[str]
    limits: dict[str, int] = field(default_factory=dict)
    network_max: Literal["none", "egress-proxy"] = "none"
    egress_domains: tuple[str, ...] | None = None

    @classmethod
    def from_config(cls, c: dict[str, Any]) -> Principal:
        domains = c.get("egress_domains")
        return cls(
            id=c["id"],
            profiles=frozenset(c["profiles"]),
            limits=dict(c.get("limits", {})),
            network_max=c.get("network_max", "none"),
            egress_domains=tuple(domains) if domains is not None else None,
        )

    def policy_json(self) -> str:
        """The ``nsbx_policy::Principal`` passed to ``narrow()``."""
        return json.dumps(
            {
                "id": self.id,
                "profiles": sorted(self.profiles),
                "limits": self.limits,
                "network_max": self.network_max,
                "egress_domains": sorted(self.egress_domains) if self.egress_domains is not None else None,
            }
        )


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
