
from __future__ import annotations

import os

import requests

from app.dynamic_analysis.verification_service import (
    DynamicVerificationService,
)
from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
    ScanType,
)


TARGET = "http://localhost:4280/"
SQLI_ENDPOINT = (
    "http://localhost:4280/vulnerabilities/sqli/"
)


def build_session() -> requests.Session:
   

    phpsessid = os.environ.get(
        "DVWA_PHPSESSID"
    )

    if not phpsessid:
        raise RuntimeError(
            "DVWA_PHPSESSID is not set. "
            "Set the current DVWA PHP session ID before "
            "running this validation."
        )

    session = requests.Session()


    session.cookies.set(
        "PHPSESSID",
        phpsessid,
    )

    session.cookies.set(
        "security",
        "low",
    )

    return session


def build_finding() -> Finding:

    return Finding(
        finding_type=FindingType.SQL_INJECTION,
        explanation=(
            "Potential SQL injection identified during "
            "dynamic analysis."
        ),
        scan_type=ScanType.DYNAMIC,
        endpoint=SQLI_ENDPOINT,
        method="GET",
        parameter="id",
        proposed_cwe="CWE-89",
        suggested_severity="HIGH",
        status=FindingStatus.PROPOSED,
    )


def main() -> None:
    print(
        "=== PHASE 3E — DYNAMIC VERIFICATION SERVICE ==="
    )
    print()

    print("=== 1. TARGET ===")
    print(f"Application: {TARGET}")
    print(f"Endpoint: {SQLI_ENDPOINT}")
    print()

    session = build_session()

    finding = build_finding()

    print("=== 2. INPUT FINDING ===")
    print(
        f"Finding ID: {finding.finding_id}"
    )
    print(
        f"Type: {finding.finding_type.value}"
    )
    print(
        "Status before verification: "
        f"{finding.status.value}"
    )
    print(
        f"Endpoint: {finding.endpoint}"
    )
    print(
        f"Method: {finding.method}"
    )
    print(
        f"Parameter: {finding.parameter}"
    )
    print(
        f"Proposed CWE: {finding.proposed_cwe}"
    )
    print(
        "Suggested severity: "
        f"{finding.suggested_severity}"
    )
    print()

    service = DynamicVerificationService(
        session=session,
    )

    result = service.verify(
        finding
    )

    print(
        "=== 3. RESOLVED CANDIDATE ==="
    )
    print(
        f"Endpoint: {result.candidate.endpoint}"
    )
    print(
        f"Method: {result.candidate.method}"
    )
    print(
        f"Parameter: {result.candidate.parameter}"
    )
    print(
        "Observed: "
        f"{result.candidate.observed_value!r}"
    )
    print(
        "Fixed: "
        f"{result.candidate.fixed_parameters}"
    )
    print()

    print(
        "=== 4. RUNTIME EVIDENCE ==="
    )
    print(
        f"Evidence ID: {result.evidence.evidence_id}"
    )
    print(
        f"Capability: {result.evidence.capability}"
    )
    print(
        f"Endpoint: {result.evidence.endpoint}"
    )
    print(
        f"Parameter: {result.evidence.parameter}"
    )
    print(
        "Observations: "
        f"{len(result.evidence.observations)}"
    )
    print()

    for observation in result.evidence.observations:
        print(
            f"Observation: {observation.label}"
        )

        print(
            f"  Status: {observation.status_code}"
        )

        print(
            f"  Bytes: {observation.response_length}"
        )

        print(
            "  Digest: "
            f"{observation.response_digest[:12]}"
        )

        print(
            "  Error detected: "
            f"{observation.metadata.get('error_detected')}"
        )

        print(
            "  Error family: "
            f"{observation.metadata.get('error_family')}"
        )

        print(
            "  Error signature: "
            f"{observation.metadata.get('error_signature')}"
        )

        print()

    print(
        "=== 5. DETERMINISTIC VERIFICATION ==="
    )

    print(
        "Verifier: "
        f"{result.verification.verifier_id}"
    )

    print(
        "Decision: "
        f"{result.verification.decision.value}"
    )

    print(
        "Canonical finding status: "
        f"{result.finding_status.value}"
    )

    print("Reasons:")

    for reason in result.verification.reasons:
        print(
            f" - {reason}"
        )

    print("Signals used:")

    for signal in result.verification.signals_used:
        print(
            f" - {signal}"
        )

    print()

    print(
        "=== 6. ARCHITECTURE CHECK ==="
    )

    print(
        "Original Finding status: "
        f"{finding.status.value}"
    )

    if finding.status is not FindingStatus.PROPOSED:
        raise AssertionError(
            "Verification service unexpectedly mutated "
            "the original Finding."
        )

    print(
        "PASS: Original AI proposal remains PROPOSED."
    )

    if result.finding_status is not FindingStatus.PROVED:
        raise AssertionError(
            "Expected deterministic verification result "
            "PROVED for the current authorised DVWA lab, "
            f"received {result.finding_status.value}."
        )

    print(
        "PASS: Deterministic verifier independently "
        "produced PROVED."
    )

    print(
        "PASS: Human Review has not been performed."
    )

    print()

    print(
        "=== PHASE 3E RUNTIME VALIDATION COMPLETE ==="
    )


if __name__ == "__main__":
    main()