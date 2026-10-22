
from __future__ import annotations

import hashlib
import time

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

import requests

from app.dynamic_analysis.evidence.models import (
    EvidenceBundle,
    RuntimeObservation,
)
from app.dynamic_analysis.evidence.response_signals import (
    ResponseSignalExtractor,
)
from app.dynamic_analysis.probes.base import DynamicProbe


@dataclass(frozen=True)
class InjectionProbeInput:
    endpoint: str
    method: str
    parameter: str
    baseline_value: str
    test_values: tuple[str, ...]
    fixed_parameters: Mapping[str, str] | None = None

    def __post_init__(self):
        if not self.endpoint.strip():
            raise ValueError(
                "endpoint must not be empty."
            )

        if self.method.upper() not in {"GET", "POST"}:
            raise ValueError(
                "method must be GET or POST."
            )

        if not self.parameter.strip():
            raise ValueError(
                "parameter must not be empty."
            )

        if not self.test_values:
            raise ValueError(
                "at least one test value is required."
            )


class InjectionDifferentialProbe(DynamicProbe):
    probe_id = "injection-differential-probe"
    capability = "INJECTION_DIFFERENTIAL"

    def __init__(
        self,
        *,
        timeout_seconds=10,
        max_digest_bytes=1_000_000,
        signal_extractor=None,
    ):
        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be greater than zero."
            )

        if max_digest_bytes <= 0:
            raise ValueError(
                "max_digest_bytes must be greater than zero."
            )

        self.timeout_seconds = timeout_seconds
        self.max_digest_bytes = max_digest_bytes

        self.signal_extractor = (
            signal_extractor
            if signal_extractor is not None
            else ResponseSignalExtractor()
        )

    def supports(self, context: Any) -> bool:
        return isinstance(
            context,
            InjectionProbeInput,
        )

    def collect(
        self,
        *,
        context: Any,
        session: Any,
    ) -> EvidenceBundle:
        if not self.supports(context):
            raise TypeError(
                "context must be an InjectionProbeInput."
            )

        if not isinstance(
            session,
            requests.Session,
        ):
            raise TypeError(
                "session must be a requests.Session."
            )

        observations = [
            self._observe(
                session,
                context,
                context.baseline_value,
                "BASELINE",
            )
        ]

        for index, value in enumerate(
            context.test_values,
            1,
        ):
            observations.append(
                self._observe(
                    session,
                    context,
                    value,
                    f"TEST_{index}",
                )
            )

        return EvidenceBundle(
            evidence_id=(
                f"evidence-{uuid4().hex}"
            ),
            capability=self.capability,
            endpoint=context.endpoint,
            method=context.method.upper(),
            observations=tuple(observations),
            parameter=context.parameter,
            baseline_observation_id=(
                observations[0].observation_id
            ),
            metadata={
                "probe_id": self.probe_id,
                "test_count": len(
                    context.test_values
                ),
            },
        )

    def _observe(
        self,
        session,
        context,
        value,
        label,
    ):
        parameters = dict(
            context.fixed_parameters or {}
        )

        parameters[
            context.parameter
        ] = value

        method = context.method.upper()

        started = time.perf_counter()

        if method == "GET":
            response = session.get(
                context.endpoint,
                params=parameters,
                timeout=self.timeout_seconds,
                allow_redirects=True,
            )
        else:
            response = session.post(
                context.endpoint,
                data=parameters,
                timeout=self.timeout_seconds,
                allow_redirects=True,
            )

        elapsed = (
            time.perf_counter() - started
        ) * 1000.0

        digest = hashlib.sha256(
            response.content[
                : self.max_digest_bytes
            ]
        ).hexdigest()

        signals = self.signal_extractor.extract(
            response.text
        )

        return RuntimeObservation(
            observation_id=(
                f"observation-{uuid4().hex}"
            ),
            label=label,
            method=method,
            url=response.url,
            status_code=response.status_code,
            response_length=len(
                response.content
            ),
            elapsed_ms=elapsed,
            response_digest=digest,
            metadata={
                "parameter":
                    context.parameter,
                "redirect_count":
                    len(response.history),
                "content_type":
                    response.headers.get(
                        "Content-Type"
                    ),
                "error_detected":
                    signals.error_detected,
                "error_family":
                    signals.error_family,
                "error_signature":
                    signals.error_signature,
            },
        )