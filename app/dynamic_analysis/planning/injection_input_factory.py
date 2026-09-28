"""Build injection-probe inputs from neutral discovery candidates."""

from __future__ import annotations

import requests

from app.dynamic_analysis.planning.baseline_resolver import BaselineResolver
from app.dynamic_analysis.planning.injection_observation_policy import (
    InjectionObservationPolicy,
)
from app.dynamic_analysis.planning.models import ProbeCandidate
from app.dynamic_analysis.probes.injection.probe import InjectionProbeInput


class InjectionProbeInputFactory:
    """Convert a candidate into a controlled InjectionProbeInput.

    ``build`` preserves the previous pure-planning behaviour.
    ``build_with_resolved_baseline`` is the runtime-aware path for candidates
    whose discovery result did not contain an observed value.
    """

    def __init__(
        self,
        *,
        policy: InjectionObservationPolicy | None = None,
        baseline_resolver: BaselineResolver | None = None,
    ) -> None:
        self.policy = policy or InjectionObservationPolicy()
        self.baseline_resolver = baseline_resolver or BaselineResolver()

    def build(
        self,
        candidate: ProbeCandidate,
        *,
        fixed_parameters: dict[str, str] | None = None,
    ) -> InjectionProbeInput:
        if not isinstance(candidate, ProbeCandidate):
            raise TypeError("candidate must be a ProbeCandidate.")

        plan = self.policy.plan(candidate)
        merged_fixed = self._merge_fixed_parameters(
            candidate,
            fixed_parameters,
        )
        return self._input(
            candidate=candidate,
            baseline_value=plan.baseline_value,
            test_values=plan.test_values,
            fixed_parameters=merged_fixed,
        )

    def build_with_resolved_baseline(
        self,
        candidate: ProbeCandidate,
        *,
        session: requests.Session,
        fixed_parameters: dict[str, str] | None = None,
    ) -> InjectionProbeInput:
        if not isinstance(candidate, ProbeCandidate):
            raise TypeError("candidate must be a ProbeCandidate.")

        merged_fixed = self._merge_fixed_parameters(
            candidate,
            fixed_parameters,
        )

        resolution = self.baseline_resolver.resolve(
            candidate,
            session=session,
            fixed_parameters=merged_fixed,
        )

        # Re-plan using the resolved value as observational metadata. This
        # preserves the capability policy while replacing only the baseline.
        resolved_candidate = ProbeCandidate(
            endpoint=candidate.endpoint,
            method=candidate.method,
            parameter=candidate.parameter,
            parameter_location=candidate.parameter_location,
            input_type=candidate.input_type,
            source=candidate.source,
            observed_value=resolution.value,
            fixed_parameters=dict(candidate.fixed_parameters),
        )
        plan = self.policy.plan(resolved_candidate)

        return self._input(
            candidate=candidate,
            baseline_value=resolution.value,
            test_values=plan.test_values,
            fixed_parameters=merged_fixed,
        )

    @staticmethod
    def _merge_fixed_parameters(
        candidate: ProbeCandidate,
        explicit: dict[str, str] | None,
    ) -> dict[str, str]:
        merged = dict(candidate.fixed_parameters)
        merged.update(explicit or {})
        merged.pop(candidate.parameter, None)
        return merged

    @staticmethod
    def _input(
        *,
        candidate: ProbeCandidate,
        baseline_value: str,
        test_values: tuple[str, ...],
        fixed_parameters: dict[str, str] | None,
    ) -> InjectionProbeInput:
        return InjectionProbeInput(
            endpoint=candidate.endpoint,
            method=candidate.method,
            parameter=candidate.parameter,
            baseline_value=baseline_value,
            test_values=test_values,
            fixed_parameters=dict(fixed_parameters or {}),
        )
