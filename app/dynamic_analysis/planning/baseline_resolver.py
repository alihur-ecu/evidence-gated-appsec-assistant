"""Resolve a repeatable baseline for active dynamic observation.

The resolver is target-neutral. It does not infer a vulnerability and does not
contain application-specific parameter names, paths, or expected values.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable

import requests

from app.dynamic_analysis.planning.models import ProbeCandidate


@dataclass(frozen=True)
class BaselineResolution:
    value: str
    source: str
    status_code: int
    response_length: int
    response_digest: str
    repeatable: bool


@dataclass(frozen=True)
class BaselineResolutionPolicy:
    """Conservative candidate values used only when discovery saw no value."""

    text_candidates: tuple[str, ...] = ("1", "test", "0")
    numeric_candidates: tuple[str, ...] = ("1", "0", "2")
    repeat_count: int = 2
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not self.text_candidates:
            raise ValueError("text_candidates must not be empty.")
        if not self.numeric_candidates:
            raise ValueError("numeric_candidates must not be empty.")
        if self.repeat_count < 2:
            raise ValueError("repeat_count must be at least 2.")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")


class BaselineResolver:
    """Find a stable baseline without vulnerability-specific assumptions."""

    def __init__(
        self,
        *,
        policy: BaselineResolutionPolicy | None = None,
    ) -> None:
        self.policy = policy or BaselineResolutionPolicy()

    def resolve(
        self,
        candidate: ProbeCandidate,
        *,
        session: requests.Session,
        fixed_parameters: dict[str, str] | None = None,
    ) -> BaselineResolution:
        if not isinstance(candidate, ProbeCandidate):
            raise TypeError("candidate must be a ProbeCandidate.")

        fixed = dict(candidate.fixed_parameters)
        fixed.update(fixed_parameters or {})
        fixed.pop(candidate.parameter, None)

        observed_result: BaselineResolution | None = None

        if candidate.observed_value is not None:
            observations = self._repeat(
                candidate=candidate,
                value=candidate.observed_value,
                session=session,
                fixed_parameters=fixed,
            )
            observed_result = self._resolution(
                value=candidate.observed_value,
                source="OBSERVED",
                observations=observations,
            )

            # A non-empty observed value is the strongest target-derived
            # baseline when it is stable and successful.
            if (
                candidate.observed_value != ""
                and observed_result.repeatable
                and 200 <= observed_result.status_code < 400
            ):
                return observed_result

        candidates = (
            self.policy.numeric_candidates
            if self._is_numeric(candidate)
            else self.policy.text_candidates
        )

        fallback: BaselineResolution | None = None

        for value in candidates:
            observations = self._repeat(
                candidate=candidate,
                value=value,
                session=session,
                fixed_parameters=fixed,
            )
            result = self._resolution(
                value=value,
                source="SYNTHETIC",
                observations=observations,
            )

            if fallback is None:
                fallback = result

            if result.repeatable and 200 <= result.status_code < 400:
                return result

        if observed_result is not None:
            # Preserve the observed response as a conservative fallback if no
            # synthetic candidate produced a stable successful baseline.
            return observed_result

        if fallback is None:
            raise RuntimeError("baseline policy produced no candidate values.")

        return fallback

    def _repeat(
        self,
        *,
        candidate: ProbeCandidate,
        value: str,
        session: requests.Session,
        fixed_parameters: dict[str, str],
    ) -> list[tuple[int, int, str]]:
        return [
            self._request(
                candidate=candidate,
                value=value,
                session=session,
                fixed_parameters=fixed_parameters,
            )
            for _ in range(self.policy.repeat_count)
        ]

    def _request(
        self,
        *,
        candidate: ProbeCandidate,
        value: str,
        session: requests.Session,
        fixed_parameters: dict[str, str],
    ) -> tuple[int, int, str]:
        parameters = dict(fixed_parameters)
        parameters[candidate.parameter] = value

        kwargs = {
            "timeout": self.policy.timeout_seconds,
            "allow_redirects": True,
        }

        if candidate.method.upper() == "GET":
            response = session.get(
                candidate.endpoint,
                params=parameters,
                **kwargs,
            )
        elif candidate.method.upper() == "POST":
            response = session.post(
                candidate.endpoint,
                data=parameters,
                **kwargs,
            )
        else:
            raise ValueError("candidate method must be GET or POST.")

        body = response.content
        digest = hashlib.sha256(body).hexdigest()
        return response.status_code, len(body), digest

    @staticmethod
    def _resolution(
        *,
        value: str,
        source: str,
        observations: Iterable[tuple[int, int, str]],
    ) -> BaselineResolution:
        observations = list(observations)
        first = observations[0]
        repeatable = all(item == first for item in observations[1:])

        return BaselineResolution(
            value=value,
            source=source,
            status_code=first[0],
            response_length=first[1],
            response_digest=first[2],
            repeatable=repeatable,
        )

    @staticmethod
    def _is_numeric(candidate: ProbeCandidate) -> bool:
        return (candidate.input_type or "").lower() in {"number", "range"}
