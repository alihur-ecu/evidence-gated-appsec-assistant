
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.dynamic_analysis.evidence import EvidenceBundle


class DynamicProbe(ABC):


    probe_id: str
    capability: str

    @abstractmethod
    def supports(self, context: Any) -> bool:
        """"""

    @abstractmethod
    def collect(
        self,
        *,
        context: Any,
        session: Any,
    ) -> EvidenceBundle:
        """"""
