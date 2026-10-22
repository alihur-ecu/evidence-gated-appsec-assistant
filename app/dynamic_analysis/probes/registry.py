from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.dynamic_analysis.probes.base import DynamicProbe


class ProbeRegistry:


    def __init__(self, probes: Iterable[DynamicProbe] = ()) -> None:
        self._probes: dict[str, DynamicProbe] = {}
        for probe in probes:
            self.register(probe)

    def register(self, probe: DynamicProbe) -> None:
        if not isinstance(probe, DynamicProbe):
            raise TypeError("probe must implement DynamicProbe.")

        probe_id = getattr(probe, "probe_id", "")
        capability = getattr(probe, "capability", "")

        if not isinstance(probe_id, str) or not probe_id.strip():
            raise ValueError("probe.probe_id must be a non-empty string.")
        if not isinstance(capability, str) or not capability.strip():
            raise ValueError("probe.capability must be a non-empty string.")
        if probe_id in self._probes:
            raise ValueError(f"probe_id already registered: {probe_id}")

        self._probes[probe_id] = probe

    def get(self, probe_id: str) -> DynamicProbe:
        try:
            return self._probes[probe_id]
        except KeyError as exc:
            raise KeyError(f"Unknown probe_id: {probe_id}") from exc

    def applicable(self, context: Any) -> tuple[DynamicProbe, ...]:
        return tuple(
            probe
            for probe in self._probes.values()
            if probe.supports(context)
        )

    def all(self) -> tuple[DynamicProbe, ...]:
        return tuple(self._probes.values())

    def __len__(self) -> int:
        return len(self._probes)
