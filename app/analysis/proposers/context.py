from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AnalysisContext:

    context_id: str
    scan_type: str
    content: str

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        context_id = self.context_id.strip()

        if not context_id:
            raise ValueError(
                "context_id must not be empty."
            )

        scan_type = self.scan_type.strip().upper()

        if not scan_type:
            raise ValueError(
                "scan_type must not be empty."
            )

        if not isinstance(self.content, str):
            raise TypeError(
                "content must be a string."
            )

        if not isinstance(self.metadata, dict):
            raise TypeError(
                "metadata must be a dictionary."
            )

        object.__setattr__(
            self,
            "context_id",
            context_id,
        )

        object.__setattr__(
            self,
            "scan_type",
            scan_type,
        )

        # Defensive copy prevents callers from later mutating the
        # dictionary originally supplied to this frozen context.
        object.__setattr__(
            self,
            "metadata",
            dict(self.metadata),
        )

    @property
    def char_count(self) -> int:
        

        return len(self.content)

    def to_dict(self) -> dict[str, Any]:
        

        return asdict(self)