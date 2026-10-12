from __future__ import annotations

import pytest

from app.dynamic_analysis.verification_router import (
    VerificationCapability,
    VerificationMode,
    VerificationReadiness,
    VerificationRouter,
    route_finding_for_verification,
)

from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
    ScanType,
)


def _finding(
    **overrides,
) -> Finding:

    values = {
        "finding_type":
            FindingType.SQL_INJECTION,

        "explanation":
            "Candidate proposed by analysis.",

        "scan_type":
            ScanType.DYNAMIC,

        "endpoint":
            (
                "http://localhost:4280/"
                "vulnerabilities/sqli/"
            ),

        "method":
            "GET",

        "parameter":
            "id",

        "status":
            FindingStatus.PROPOSED,
    }

    values.update(
        overrides
    )

    return Finding(
        **values
    )


def test_sql_injection_with_runtime_context_is_ready():

    route = (
        route_finding_for_verification(
            _finding()
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.READY
    )

    assert route.can_verify is True

    assert (
        route.capability_id
        == "INJECTION_DIFFERENTIAL"
    )

    assert (
        route.verifier_id
        == "injection_differential"
    )

    assert (
        route.mode
        is VerificationMode.RUNTIME
    )

    assert (
        route.missing_fields
        == ()
    )


def test_static_sql_injection_routes_to_static_source_verifier():

    route = (
        route_finding_for_verification(
            _finding(
                scan_type=
                    ScanType.STATIC,

                endpoint=None,
                method=None,
                parameter="id",
            )
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.READY
    )

    assert route.can_verify is True

    assert (
        route.capability_id
        == "STATIC_SQL_INJECTION_SOURCE"
    )

    assert (
        route.verifier_id
        == "static_sql_injection_source"
    )

    assert (
        route.mode
        is VerificationMode.STATIC
    )

    assert (
        route.missing_fields
        == ()
    )


def test_xss_static_source_observation_capability_is_available():

    finding = _finding(
        finding_type=
            FindingType.XSS,

        scan_type=
            ScanType.STATIC,

        endpoint=None,
        method=None,
        parameter="bio",

        proposed_cwe=
            "CWE-79",
    )

    route = (
        route_finding_for_verification(
            finding
        )
    )

    assert (
        finding.status
        is FindingStatus.PROPOSED
    )

    assert (
        route.readiness
        is VerificationReadiness.READY
    )

    assert route.can_verify is True

    assert route.capability_id == "STATIC_XSS_SOURCE_OBSERVATION"

    assert (
        "capability is ready"
        in route.reason.lower()
    )


def test_unknown_future_vulnerability_label_is_not_discarded():

    finding = _finding(
        finding_type=
            FindingType.OTHER,

        raw_finding_type=
            "FUTURE_PATCH_VULNERABILITY",

        scan_type=
            ScanType.STATIC,

        endpoint=None,
        method=None,
        parameter=None,
    )

    route = (
        route_finding_for_verification(
            finding
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.UNSUPPORTED
    )

    assert (
        route.raw_finding_type
        == "FUTURE_PATCH_VULNERABILITY"
    )

    assert (
        finding.raw_finding_type
        == "FUTURE_PATCH_VULNERABILITY"
    )

    assert (
        finding.status
        is FindingStatus.PROPOSED
    )


def test_non_proposed_finding_is_not_eligible_for_reverification():

    route = (
        route_finding_for_verification(
            _finding(
                status=
                    FindingStatus.NEEDS_HUMAN
            )
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.NOT_ELIGIBLE
    )

    assert (
        route.can_verify
        is False
    )


def test_new_vulnerability_support_is_additive_through_registration():

    xss_capability = VerificationCapability(
        capability_id=
            "XSS_RUNTIME_TEST",

        verifier_id=
            "xss_runtime_verifier",

        mode=
            VerificationMode.RUNTIME,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),

        required_fields=(
            "endpoint",
            "method",
            "parameter",
        ),
    )

    router = (
        VerificationRouter()
    )

    router.register(
        xss_capability
    )

    route = router.route(
        _finding(
            finding_type=
                FindingType.XSS,

            endpoint=
                "http://localhost:4280/profile",

            method=
                "POST",

            parameter=
                "bio",
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.READY
    )

    assert (
        route.capability_id
        == "XSS_RUNTIME_TEST"
    )

    assert (
        route.verifier_id
        == "xss_runtime_verifier"
    )


def test_future_static_capability_can_require_source_context_instead_of_http():

    source_capability = VerificationCapability(
        capability_id=
            "SOURCE_LITERAL_CHECK",

        verifier_id=
            "source_literal_verifier",

        mode=
            VerificationMode.STATIC,

        finding_types=
            frozenset({
                FindingType.OTHER,
            }),

        required_fields=(
            "source_file",
            "line_number",
        ),
    )

    router = VerificationRouter(
        (
            source_capability,
        )
    )

    route = router.route(
        _finding(
            finding_type=
                FindingType.OTHER,

            raw_finding_type=
                "Hardcoded Password",

            scan_type=
                ScanType.STATIC,

            endpoint=None,
            method=None,
            parameter=None,

            source_file=
                "database.py",

            line_number=
                42,
        )
    )

    assert (
        route.readiness
        is VerificationReadiness.READY
    )

    assert (
        route.mode
        is VerificationMode.STATIC
    )

    assert (
        route.missing_fields
        == ()
    )


def test_duplicate_capability_id_is_rejected():

    capability = VerificationCapability(
        capability_id=
            "CUSTOM",

        verifier_id=
            "custom_verifier",

        mode=
            VerificationMode.RUNTIME,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),
    )

    router = VerificationRouter(
        (
            capability,
        )
    )

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        router.register(
            capability
        )


def test_capabilities_for_different_modes_are_not_ambiguous():

    runtime_capability = VerificationCapability(
        capability_id=
            "XSS_RUNTIME",

        verifier_id=
            "xss_runtime",

        mode=
            VerificationMode.RUNTIME,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),
    )

    static_capability = VerificationCapability(
        capability_id=
            "XSS_STATIC",

        verifier_id=
            "xss_static",

        mode=
            VerificationMode.STATIC,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),
    )

    router = VerificationRouter(
        (
            runtime_capability,
            static_capability,
        )
    )

    runtime_route = router.route(
        _finding(
            finding_type=
                FindingType.XSS,

            scan_type=
                ScanType.DYNAMIC,
        )
    )

    static_route = router.route(
        _finding(
            finding_type=
                FindingType.XSS,

            scan_type=
                ScanType.STATIC,

            endpoint=None,
            method=None,
        )
    )

    assert (
        runtime_route.capability_id
        == "XSS_RUNTIME"
    )

    assert (
        static_route.capability_id
        == "XSS_STATIC"
    )


def test_ambiguous_capability_mapping_within_same_mode_fails_explicitly():

    first = VerificationCapability(
        capability_id=
            "XSS_RUNTIME_A",

        verifier_id=
            "xss_runtime_a",

        mode=
            VerificationMode.RUNTIME,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),
    )

    second = VerificationCapability(
        capability_id=
            "XSS_RUNTIME_B",

        verifier_id=
            "xss_runtime_b",

        mode=
            VerificationMode.RUNTIME,

        finding_types=
            frozenset({
                FindingType.XSS,
            }),
    )

    router = VerificationRouter(
        (
            first,
            second,
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "multiple verification capabilities"
        ),
    ):
        router.route(
            _finding(
                finding_type=
                    FindingType.XSS,

                scan_type=
                    ScanType.DYNAMIC,
            )
        )


def test_route_serialises_cleanly_for_future_web_integration():

    data = (
        route_finding_for_verification(
            _finding()
        ).to_dict()
    )

    assert data == {
        "readiness":
            "READY",

        "can_verify":
            True,

        "finding_type":
            "SQL_INJECTION",

        "raw_finding_type":
            None,

        "capability_id":
            "INJECTION_DIFFERENTIAL",

        "verifier_id":
            "injection_differential",

        "mode":
            "RUNTIME",

        "missing_fields":
            [],

        "reason":
            (
                "Independent verification "
                "capability is ready."
            ),
    }