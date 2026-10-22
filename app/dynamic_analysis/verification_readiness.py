from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint, DiscoveredForm, DiscoveredParameter, DiscoveryResult,
)
from app.dynamic_analysis.planning.candidate_builder import ProbeCandidateBuilder
from app.dynamic_analysis.planning.models import ProbeCandidate
from app.dynamic_analysis.target import build_dynamic_target
from app.dynamic_analysis.verification_service import DynamicVerificationService
from app.models.finding import Finding


@dataclass(frozen=True)
class CandidatePreflight:
    status: str
    reason: str
    candidate: ProbeCandidate | None = None

    @property
    def ready(self) -> bool:
        return self.status == "READY" and self.candidate is not None


def _parameters(items: object) -> tuple[DiscoveredParameter, ...]:
    if not isinstance(items, list):
        return ()
    result = []
    for value in items:
        if not isinstance(value, dict):
            continue
        name = value.get("name")
        location = value.get("location")
        if not isinstance(name, str) or not name.strip():
            continue
        if location not in {"query", "body"}:
            continue
        result.append(DiscoveredParameter(
            name=name,
            location=location,
            input_type=value.get("input_type") if isinstance(value.get("input_type"), str) else None,
            observed_value=value.get("observed_value") if isinstance(value.get("observed_value"), str) else None,
        ))
    return tuple(result)


def candidates_from_saved_discovery(snapshot: dict, target_url: str) -> tuple[ProbeCandidate, ...]:
    
    if not isinstance(snapshot, dict):
        raise ValueError("Saved discovery must be an object.")
    target = build_dynamic_target(target_url)
    endpoints = []
    forms = []
    for item in snapshot.get("endpoints", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        method = str(item.get("method", "")).upper()
        if not isinstance(url, str) or method not in {"GET", "POST"}:
            continue
        if not target.is_same_origin(url):
            continue
        endpoints.append(DiscoveredEndpoint(
            url=url, method=method, parameters=_parameters(item.get("parameters")),
        ))
    for item in snapshot.get("forms", []):
        if not isinstance(item, dict):
            continue
        action = item.get("action_url")
        source = item.get("source_url")
        method = str(item.get("method", "")).upper()
        if not isinstance(action, str) or not isinstance(source, str) or method not in {"GET", "POST"}:
            continue
        if not target.is_same_origin(action):
            continue
        forms.append(DiscoveredForm(
            source_url=source, action_url=action, method=method,
            parameters=_parameters(item.get("parameters")),
        ))
    discovery = DiscoveryResult(target=target, endpoints=endpoints, forms=forms)
    return ProbeCandidateBuilder().build(discovery)


def preflight_saved_candidate(
    finding: Finding, snapshot: dict, target_url: str,
) -> CandidatePreflight:
    
    try:
        candidates = candidates_from_saved_discovery(snapshot, target_url)
        expected_endpoint = DynamicVerificationService._canonical_endpoint(finding.endpoint or "")
        expected_method = (finding.method or "").strip().upper()
        expected_parameter = (finding.parameter or "").strip()
        # Do not permit a proposed URL to redirect the probe to another origin.
        if not build_dynamic_target(target_url).is_same_origin(finding.endpoint or ""):
            return CandidatePreflight(
                "CANDIDATE_NOT_DISCOVERED",
                "The proposed endpoint is outside the authorised dynamic target. No runtime test was started.",
            )
        matches = tuple(candidate for candidate in candidates if (
            DynamicVerificationService._canonical_endpoint(candidate.endpoint) == expected_endpoint
            and candidate.method.upper() == expected_method
            and candidate.parameter == expected_parameter
        ))
    except (TypeError, ValueError) as error:
        return CandidatePreflight(
            "CANDIDATE_NOT_DISCOVERED",
            "Saved discovery is not usable for matching this finding. No runtime test was started.",
        )

    if len(matches) == 1:
        return CandidatePreflight(
            "READY", "One matching request candidate was observed during dynamic discovery.", matches[0],
        )
    if len(matches) > 1:
        return CandidatePreflight(
            "CANDIDATE_AMBIGUOUS",
            "Multiple discovered request candidates match. Manual clarification is required before active testing.",
        )
    return CandidatePreflight(
        "CANDIDATE_NOT_DISCOVERED",
        "The original dynamic scan did not discover a matching editable endpoint, HTTP method and parameter. The proposal remains unverified.",
    )
