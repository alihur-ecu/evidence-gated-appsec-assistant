import os
import requests

from app.dynamic_analysis.target import build_dynamic_target
from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.planning import (
    ProbeCandidateBuilder,
    InjectionProbeInputFactory,
)
from app.dynamic_analysis.probes.injection.probe import InjectionDifferentialProbe
from app.dynamic_analysis.verifiers.injection.verifier import InjectionDifferentialVerifier


def main():
    if "DVWA_PHPSESSID" not in os.environ:
        raise RuntimeError(
            "DVWA_PHPSESSID is not defined in this PowerShell session."
        )

    session = requests.Session()
    session.cookies.set(
        "PHPSESSID",
        os.environ["DVWA_PHPSESSID"],
        path="/",
    )
    session.cookies.set("security", "low", path="/")

    target_url = "http://localhost:4280/vulnerabilities/sqli/"

    print("=== 1. DISCOVERY ===")
    target = build_dynamic_target(target_url)
    discovery = DynamicDiscovery(session=session).discover(target)
    print("Pages:", len(discovery.pages))
    print("Endpoints:", len(discovery.endpoints))
    print("Forms:", len(discovery.forms))

    print()
    print("=== 2. CANDIDATE ===")
    candidates = ProbeCandidateBuilder().build(discovery)

    candidate = next(
        item
        for item in candidates
        if item.endpoint == target_url and item.parameter == "id"
    )

    print("Endpoint:", candidate.endpoint)
    print("Method:", candidate.method)
    print("Parameter:", candidate.parameter)
    print("Observed:", repr(candidate.observed_value))
    print("Fixed:", candidate.fixed_parameters)

    print()
    print("=== 3. RESOLVED PROBE INPUT ===")
    probe_input = InjectionProbeInputFactory().build_with_resolved_baseline(
        candidate,
        session=session,
    )

    print("Baseline:", repr(probe_input.baseline_value))
    print("Fixed:", probe_input.fixed_parameters)
    print("Tests:", [repr(value) for value in probe_input.test_values])

    print()
    print("=== 4. RUNTIME EVIDENCE ===")
    evidence = InjectionDifferentialProbe().collect(
        context=probe_input,
        session=session,
    )

    print("Evidence ID:", evidence.evidence_id)
    print("Capability:", evidence.capability)
    print("Endpoint:", evidence.endpoint)
    print("Parameter:", evidence.parameter)
    print("Observations:", len(evidence.observations))

    for observation in evidence.observations:
        metadata = observation.metadata

        print()
        print("Observation:", observation.label)
        print("  Status:", observation.status_code)
        print("  Bytes:", observation.response_length)
        print(
            "  Digest:",
            observation.response_digest[:12]
            if observation.response_digest
            else None,
        )
        print("  Content-Type:", metadata.get("content_type"))
        print("  Error detected:", metadata.get("error_detected"))
        print("  Error family:", metadata.get("error_family"))
        print("  Error signature:", metadata.get("error_signature"))

    print()
    print("=== 5. DETERMINISTIC VERIFICATION ===")
    result = InjectionDifferentialVerifier().verify(evidence)

    print("Verifier:", result.verifier_id)
    print("Decision:", result.decision.value)
    print("Reasons:")
    for reason in result.reasons:
        print(" -", reason)

    print("Signals used:")
    for signal in result.signals_used:
        print(" -", signal)

    print()
    print("=== END-TO-END VALIDATION COMPLETE ===")


if __name__ == "__main__":
    main()
