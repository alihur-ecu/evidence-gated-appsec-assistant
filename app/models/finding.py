"""
Data model for candidate vulnerability findings.

A Finding starts as a PROPOSED candidate created by the LLM Proposer.
It is never confirmed by the LLM itself — only the Oracle and the
Evidence Gate are allowed to change its status after independent
verification.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class FindingType(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"  # not used in MVP, reserved for future extension


class FindingStatus(str, Enum):
    PROPOSED = "PROPOSED"        # created by the LLM, not yet verified
    PROVED = "PROVED"            # Oracle confirmed it with evidence
    REFUTED = "REFUTED"          # Oracle found evidence against it
    NEEDS_HUMAN = "NEEDS_HUMAN"  # evidence was inconclusive


@dataclass
class Finding:
    finding_type: FindingType
    endpoint: str
    parameter: str
    method: str
    explanation: str
    status: FindingStatus = FindingStatus.PROPOSED
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    confidence: Optional[float] = None  # LLM's own confidence, NEVER used as proof
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["finding_type"] = self.finding_type.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = dict(data)
        data["finding_type"] = FindingType(data["finding_type"])
        data["status"] = FindingStatus(data["status"])
        return cls(**data)