"""Build neutral active-observation candidates from read-only discovery."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import parse_qs, urlsplit, urlunsplit

from app.dynamic_analysis.discovery import DiscoveryResult, DiscoveredParameter
from app.dynamic_analysis.planning.models import ProbeCandidate


_EXCLUDED_INPUT_TYPES = frozenset({
    "button",
    "checkbox",
    "file",
    "hidden",
    "image",
    "radio",
    "reset",
    "submit",
})


class ProbeCandidateBuilder:
    """Select mutable surfaces and preserve reproducible request context.

    Primary probe targets remain editable controls. Sibling controls with
    values observed during discovery are retained as fixed request context.
    No application names, paths, parameter names, or vulnerability-specific
    assumptions are used here.
    """

    def build(self, discovery: DiscoveryResult) -> tuple[ProbeCandidate, ...]:
        if not isinstance(discovery, DiscoveryResult):
            raise TypeError("discovery must be a DiscoveryResult.")

        candidates: list[ProbeCandidate] = []
        seen: dict[tuple[str, str, str, str], int] = {}

        for endpoint in discovery.endpoints:
            canonical_endpoint = self._canonical_endpoint(endpoint.url)
            query_values = self._query_values(endpoint.url)

            for parameter in endpoint.parameters:
                observed_value = (
                    parameter.observed_value
                    if parameter.observed_value is not None
                    else self._observed_value(
                        parameter=parameter,
                        query_values=query_values,
                    )
                )

                candidate = self._make_candidate(
                    endpoint=canonical_endpoint,
                    method=endpoint.method,
                    parameter=parameter,
                    source="ENDPOINT",
                    observed_value=observed_value,
                    fixed_parameters={},
                )
                if candidate is not None:
                    self._append_or_enrich(
                        candidates,
                        seen,
                        candidate,
                    )

        for form in discovery.forms:
            canonical_endpoint = self._canonical_endpoint(form.action_url)

            for parameter in form.parameters:
                fixed_parameters = self._form_fixed_parameters(
                    form.parameters,
                    target_parameter=parameter.name,
                )

                candidate = self._make_candidate(
                    endpoint=canonical_endpoint,
                    method=form.method,
                    parameter=parameter,
                    source="FORM",
                    observed_value=parameter.observed_value,
                    fixed_parameters=fixed_parameters,
                )
                if candidate is not None:
                    self._append_or_enrich(
                        candidates,
                        seen,
                        candidate,
                    )

        return tuple(candidates)

    @staticmethod
    def _canonical_endpoint(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    @staticmethod
    def _query_values(url: str) -> dict[str, list[str]]:
        return parse_qs(
            urlsplit(url).query,
            keep_blank_values=True,
            strict_parsing=False,
        )

    @staticmethod
    def _observed_value(
        *,
        parameter: DiscoveredParameter,
        query_values: dict[str, list[str]],
    ) -> str | None:
        if parameter.location.strip().lower() != "query":
            return None

        values = query_values.get(parameter.name)
        if not values:
            return None

        return values[0]

    @staticmethod
    def _form_fixed_parameters(
        parameters: tuple[DiscoveredParameter, ...],
        *,
        target_parameter: str,
    ) -> dict[str, str]:
        fixed: dict[str, str] = {}

        for parameter in parameters:
            name = parameter.name.strip()

            if not name or name == target_parameter:
                continue

            if parameter.observed_value is None:
                continue

            fixed.setdefault(
                name,
                parameter.observed_value,
            )

        return fixed

    @staticmethod
    def _make_candidate(
        *,
        endpoint: str,
        method: str,
        parameter: DiscoveredParameter,
        source: str,
        observed_value: str | None,
        fixed_parameters: dict[str, str],
    ) -> ProbeCandidate | None:
        method = method.upper()
        if method not in {"GET", "POST"}:
            return None

        location = parameter.location.strip().lower()
        if location not in {"query", "body"}:
            return None

        input_type = (
            parameter.input_type.strip().lower()
            if parameter.input_type
            else None
        )

        if input_type in _EXCLUDED_INPUT_TYPES:
            return None

        name = parameter.name.strip()
        if not name:
            return None

        fixed_parameters = dict(fixed_parameters)
        fixed_parameters.pop(name, None)

        return ProbeCandidate(
            endpoint=endpoint,
            method=method,
            parameter=name,
            parameter_location=location,
            input_type=input_type,
            source=source,
            observed_value=observed_value,
            fixed_parameters=fixed_parameters,
        )

    @staticmethod
    def _append_or_enrich(
        candidates: list[ProbeCandidate],
        seen: dict[tuple[str, str, str, str], int],
        candidate: ProbeCandidate,
    ) -> None:
        key = (
            candidate.endpoint,
            candidate.method,
            candidate.parameter,
            candidate.parameter_location,
        )

        if key not in seen:
            seen[key] = len(candidates)
            candidates.append(candidate)
            return

        index = seen[key]
        existing = candidates[index]

        merged_fixed = dict(existing.fixed_parameters)
        merged_fixed.update(candidate.fixed_parameters)
        merged_fixed.pop(existing.parameter, None)

        observed_value = (
            existing.observed_value
            if existing.observed_value is not None
            else candidate.observed_value
        )

        if (
            merged_fixed != existing.fixed_parameters
            or observed_value != existing.observed_value
        ):
            candidates[index] = replace(
                existing,
                observed_value=observed_value,
                fixed_parameters=merged_fixed,
            )
