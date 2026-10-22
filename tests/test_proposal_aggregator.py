from app.analysis.proposal_aggregator import (
    ProposalAggregator,
    aggregate_analysis_result,
)


def test_exact_duplicate_is_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 198,
            "proposed_cwe": "CWE-89",
            "chunk_id": "app/users.py:80-210",
        },
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 198,
            "proposed_cwe": "CWE-89",
            "chunk_id": "app/users.py:191-320",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_received == 2
    assert result.proposals_retained == 1
    assert result.duplicates_merged == 1

    finding = result.findings[0]

    assert finding["source_file"] == (
        "app/users.py"
    )

    assert finding["line_number"] == 198

    assert finding["observed_in_chunks"] == [
        "app/users.py:80-210",
        "app/users.py:191-320",
    ]


def test_nearby_lines_from_overlap_are_merged():
    proposals = [
        {
            "finding_type": "XSS",
            "source_file": "web/profile.py",
            "line_number": 74,
            "chunk_id": "web/profile.py:1-80",
        },
        {
            "finding_type": "XSS",
            "source_file": "web/profile.py",
            "line_number": 76,
            "chunk_id": "web/profile.py:61-140",
        },
    ]

    result = ProposalAggregator(
        line_tolerance=3,
    ).aggregate(proposals)

    assert result.proposals_retained == 1
    assert result.duplicates_merged == 1


def test_same_type_different_lines_are_not_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 100,
        },
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 350,
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 2
    assert result.duplicates_merged == 0


def test_same_line_different_vulnerability_is_not_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/view.py",
            "line_number": 50,
            "proposed_cwe": "CWE-89",
        },
        {
            "finding_type": "XSS",
            "source_file": "app/view.py",
            "line_number": 50,
            "proposed_cwe": "CWE-79",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 2


def test_same_vulnerability_in_different_files_is_not_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 25,
        },
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/admin.py",
            "line_number": 25,
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 2


def test_runtime_duplicate_is_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "endpoint": "/products",
            "method": "GET",
            "parameter": "id",
            "chunk_id": "runtime-observation-1",
        },
        {
            "finding_type": "SQL_INJECTION",
            "endpoint": "/products",
            "method": "GET",
            "parameter": "id",
            "chunk_id": "runtime-observation-2",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 1

    assert (
        result.findings[0][
            "observed_in_chunks"
        ]
        == [
            "runtime-observation-1",
            "runtime-observation-2",
        ]
    )


def test_different_runtime_parameters_are_not_merged():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "endpoint": "/search",
            "method": "GET",
            "parameter": "query",
        },
        {
            "finding_type": "SQL_INJECTION",
            "endpoint": "/search",
            "method": "GET",
            "parameter": "category",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 2


def test_unknown_type_can_be_deduplicated_by_matching_label():
    proposals = [
        {
            "finding_type": "CUSTOM_SECURITY_ISSUE",
            "source_file": "service.py",
            "line_number": 44,
            "chunk_id": "service.py:1-50",
        },
        {
            "finding_type": "CUSTOM_SECURITY_ISSUE",
            "source_file": "service.py",
            "line_number": 44,
            "chunk_id": "service.py:35-90",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 1
    assert result.duplicates_merged == 1


def test_missing_line_numbers_do_not_collapse_static_findings():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "repository.py",
            "explanation": "First candidate",
        },
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "repository.py",
            "explanation": "Second candidate",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 2


def test_duplicate_can_fill_missing_metadata():
    proposals = [
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 120,
            "chunk_id": "app/users.py:1-130",
        },
        {
            "finding_type": "SQL_INJECTION",
            "source_file": "app/users.py",
            "line_number": 120,
            "proposed_cwe": "CWE-89",
            "suggested_severity": "HIGH",
            "explanation": (
                "User-controlled input reaches a SQL query."
            ),
            "chunk_id": "app/users.py:101-200",
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 1

    finding = result.findings[0]

    assert finding["proposed_cwe"] == "CWE-89"

    assert (
        finding["suggested_severity"]
        == "HIGH"
    )

    assert (
        finding["explanation"]
        == (
            "User-controlled input reaches "
            "a SQL query."
        )
    )


def test_confidence_does_not_control_deduplication():
    proposals = [
        {
            "finding_type": "XSS",
            "source_file": "view.py",
            "line_number": 90,
            "confidence": 0.10,
        },
        {
            "finding_type": "XSS",
            "source_file": "view.py",
            "line_number": 90,
            "confidence": 0.99,
        },
    ]

    result = ProposalAggregator().aggregate(
        proposals
    )

    assert result.proposals_retained == 1
    assert result.duplicates_merged == 1

    # The first provider value is preserved.
    # Confidence never acts as evidence.
    assert (
        result.findings[0]["confidence"]
        == 0.10
    )


def test_analysis_result_metadata_is_preserved():
    analysis_result = {
        "analysis_id": "A-TEST123",
        "provider": "TEST_PROVIDER",
        "analysis_mode": "STATIC",
        "application_name": "Example",
        "findings": [
            {
                "finding_type": "SQL_INJECTION",
                "source_file": "db.py",
                "line_number": 10,
                "chunk_id": "db.py:1-20",
            },
            {
                "finding_type": "SQL_INJECTION",
                "source_file": "db.py",
                "line_number": 10,
                "chunk_id": "db.py:5-30",
            },
        ],
    }

    result = aggregate_analysis_result(
        analysis_result
    )

    assert (
        result["analysis_id"]
        == "A-TEST123"
    )

    assert (
        result["provider"]
        == "TEST_PROVIDER"
    )

    assert len(result["findings"]) == 1

    assert result["aggregation"] == {
        "proposals_received": 2,
        "proposals_retained": 1,
        "duplicates_merged": 1,
    }