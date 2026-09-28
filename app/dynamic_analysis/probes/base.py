"""Base contract for extensible dynamic-analysis probes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.dynamic_analysis.evidence import EvidenceBundle


class DynamicProbe(ABC):
    """Collect runtime evidence without deciding the final finding status.

    Implementations may support different vulnerability families or runtime
    behaviours. Authentication/session creation is intentionally outside this
    contract; a prepared session/client is supplied by the caller.
    """

    probe_id: str
    capability: str

    @abstractmethod
    def supports(self, context: Any) -> bool:
        """Return whether this probe can safely operate on ``context``."""

    @abstractmethod
    def collect(
        self,
        *,
        context: Any,
        session: Any,
    ) -> EvidenceBundle:
        """Collect observations and return evidence without verifying it."""
