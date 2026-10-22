from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests

from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.evidence.models import (
    EvidenceBundle,
    VerificationResult,
)
from app.dynamic_analysis.planning.candidate_builder import (
    ProbeCandidateBuilder,
)
from app.dynamic_analysis.planning.injection_input_factory import (
    InjectionProbeInputFactory,
)
from app.dynamic_analysis.planning.models import ProbeCandidate
from app.dynamic_analysis.probes.injection.probe import (
    InjectionDifferentialProbe,
)
from app.dynamic_analysis.target import build_dynamic_target
from app.dynamic_analysis.verifiers.injection.verifier import (
    InjectionDifferentialVerifier,
)
from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
)


class DynamicVerificationError(RuntimeError):
    """"""


class UnsupportedFindingError(DynamicVerificationError):
    """"""


class CandidateNotFoundError(DynamicVerificationError):
    """"""


class AmbiguousCandidateError(DynamicVerificationError):
    """"""


@dataclass(frozen=True)
class DynamicVerificationServiceResult:
    """"""

    finding_id: str
    finding_status: FindingStatus
    candidate: ProbeCandidate
    evidence: EvidenceBundle
    verification: VerificationResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_status": self.finding_status.value,
            "candidate": self.candidate.to_dict(),
            "evidence": self.evidence.to_dict(),
            "verification": self.verification.to_dict(),
        }


class DynamicVerificationService:
    """"""

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        discovery: Any | None = None,
        candidate_builder: ProbeCandidateBuilder | None = None,
        input_factory: InjectionProbeInputFactory | None = None,
        probe: InjectionDifferentialProbe | None = None,
        verifier: InjectionDifferentialVerifier | None = None,
        saved_candidates: tuple[ProbeCandidate, ...] | None = None,
    ) -> None:
        self.session = session or requests.Session()

        self.discovery = (
            discovery
            or DynamicDiscovery(
                session=self.session,
            )
        )

        self.candidate_builder = (
            candidate_builder
            or ProbeCandidateBuilder()
        )

        self.input_factory = (
            input_factory
            or InjectionProbeInputFactory()
        )

        self.probe = (
            probe
            or InjectionDifferentialProbe()
        )

        self.verifier = (
            verifier
            or InjectionDifferentialVerifier()
        )

        self.saved_candidates = saved_candidates

    def verify(
        self,
        finding: Finding,
    ) -> DynamicVerificationServiceResult:
        """Run deterministic verification for one canonical finding."""

        self._validate_finding(finding)

        if self.saved_candidates is None:
            target = build_dynamic_target(finding.endpoint)
            discovery_result = self.discovery.discover(target)
            candidates = self.candidate_builder.build(discovery_result)
        else:
            
            candidates = self.saved_candidates

        candidate = self._resolve_candidate(
            finding,
            candidates,
        )

        probe_input = (
            self.input_factory.build_with_resolved_baseline(
                candidate,
                session=self.session,
            )
        )

        evidence = self.probe.collect(
            context=probe_input,
            session=self.session,
        )

        verification = self.verifier.verify(
            evidence
        )

        status = FindingStatus(
            verification.decision.value
        )

        return DynamicVerificationServiceResult(
            finding_id=finding.finding_id,
            finding_status=status,
            candidate=candidate,
            evidence=evidence,
            verification=verification,
        )

    @staticmethod
    def _validate_finding(
        finding: Finding,
    ) -> None:
        if not isinstance(finding, Finding):
            raise TypeError(
                "finding must be a Finding."
            )

        if finding.finding_type is not FindingType.SQL_INJECTION:
            raise UnsupportedFindingError(
                "Deterministic web verification currently "
                "supports only SQL_INJECTION findings."
            )

        if finding.status is not FindingStatus.PROPOSED:
            raise DynamicVerificationError(
                "Only PROPOSED findings may enter "
                "deterministic verification."
            )

        missing = [
            name
            for name, value in (
                ("endpoint", finding.endpoint),
                ("method", finding.method),
                ("parameter", finding.parameter),
            )
            if (
                not isinstance(value, str)
                or not value.strip()
            )
        ]

        if missing:
            raise DynamicVerificationError(
                "Dynamic verification requires finding fields: "
                + ", ".join(missing)
                + "."
            )

        if finding.method.upper() not in {
            "GET",
            "POST",
        }:
            raise DynamicVerificationError(
                "Dynamic verification currently "
                "supports GET and POST findings."
            )

    @classmethod
    def _resolve_candidate(
        cls,
        finding: Finding,
        candidates: tuple[ProbeCandidate, ...],
    ) -> ProbeCandidate:
        expected_endpoint = cls._canonical_endpoint(
            finding.endpoint
        )

        expected_method = finding.method.upper()

        expected_parameter = finding.parameter.strip()

        matches = tuple(
            candidate
            for candidate in candidates
            if (
                cls._canonical_endpoint(
                    candidate.endpoint
                )
                == expected_endpoint
                and candidate.method.upper()
                == expected_method
                and candidate.parameter
                == expected_parameter
            )
        )

        if not matches:
            raise CandidateNotFoundError(
                "No discovered probe candidate matched "
                "the finding endpoint, method, and parameter."
            )

        if len(matches) > 1:
            raise AmbiguousCandidateError(
                "Multiple discovered probe candidates "
                "matched the finding."
            )

        return matches[0]

    @staticmethod
    def _canonical_endpoint(
        url: str,
    ) -> str:
        parts = urlsplit(
            url.strip()
        )

        path = parts.path or "/"

        return urlunsplit(
            (
                parts.scheme.lower(),
                parts.netloc.lower(),
                path,
                "",
                "",
            )
        )


def verify_dynamic_finding(
    finding: Finding,
    **service_dependencies: Any,
) -> dict[str, Any]:
    """Convenience boundary for future Flask/API integration."""

    service = DynamicVerificationService(
        **service_dependencies
    )

    return service.verify(
        finding
    ).to_dict()