from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ScanType(str, Enum):
 

    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):


    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    IDOR = "IDOR"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    FILE_INCLUSION = "FILE_INCLUSION"
    FILE_UPLOAD = "FILE_UPLOAD"
    CSRF = "CSRF"
    AUTHENTICATION_RATE_LIMITING = "AUTHENTICATION_RATE_LIMITING"
    CODE_INJECTION = "CODE_INJECTION"
    INFORMATION_EXPOSURE = "INFORMATION_EXPOSURE"
    FORCED_BROWSING = "FORCED_BROWSING"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    OTHER = "OTHER"


class FindingStatus(str, Enum):
 

    PROPOSED = "PROPOSED"
    PROVED = "PROVED"
    REFUTED = "REFUTED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


@dataclass
class Finding:
  

    finding_type: FindingType
    explanation: str

    # Origin of the proposal.
    scan_type: ScanType = ScanType.UNKNOWN

    # Runtime location/context.
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None

    # Static source location/context.
    source_file: Optional[str] = None
    line_number: Optional[int] = None

    # LLM/provider proposal metadata.
    proposed_cwe: Optional[str] = None
    suggested_severity: Optional[str] = None
    confidence: Optional[float] = None

    # Preserve the provider's original vulnerability label when the
    # vulnerability cannot be normalised to a known FindingType.
    raw_finding_type: Optional[str] = None

    # Canonical lifecycle state.
    status: FindingStatus = FindingStatus.PROPOSED

    finding_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Serialize the canonical finding to a JSON-friendly dictionary."""

        data = asdict(self)

        data["finding_type"] = self.finding_type.value
        data["scan_type"] = self.scan_type.value
        data["status"] = self.status.value

        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":

        restored = dict(data)

        restored["finding_type"] = FindingType(
            restored["finding_type"]
        )

        restored["scan_type"] = ScanType(
            restored.get(
                "scan_type",
                ScanType.UNKNOWN.value,
            )
        )

        restored["status"] = FindingStatus(
            restored.get(
                "status",
                FindingStatus.PROPOSED.value,
            )
        )

        return cls(**restored)