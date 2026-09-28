import pytest

from app.analysis.proposers.base import (
    StaticProposer,
)
from app.analysis.proposers.budget import (
    LLMExecutionBudget,
)
from app.analysis.static_pipeline import (
    run_static_proposal_pipeline,
)


class FakeStaticProposer(StaticProposer):
    provider_name = "FAKE"

    def __init__(
        self,
        proposals=None,
    ):
        self.proposals = list(
            proposals or []
        )

        self.calls = []

    def propose(
        self,
        *,
        application_name,
        chunks,
    ):
        self.calls.append(
            {
                "application_name":
                    application_name,

                "chunks":
                    list(chunks),
            }
        )

        return list(
            self.proposals
        )


def make_chunk(
    chunk_id,
    source_code="print('hello')",
):
    return {
        "chunk_id": chunk_id,
        "source_file": "app/example.py",
        "language": "Python",
        "start_line": 1,
        "end_line": 1,
        "char_count": len(source_code),
        "source_code": source_code,
    }


def make_analysis(
    chunks=None,
):
    return {
        "analysis_mode": "STATIC",
        "scan_type": "STATIC",
        "application_name": "Generic Application",
        "provider": "STATIC_SOURCE",
        "context_source": "SOURCE_CODE",
        "source_context": list(
            chunks or []
        ),
        "findings": [],
    }


def make_proposal(
    *,
    line_number=10,
    chunk_id="chunk-1",
):
    return {
        "finding_type":
            "SQL_INJECTION",

        "explanation":
            "User input appears to be concatenated "
            "into a SQL statement.",

        "scan_type":
            "STATIC",

        "source_file":
            "app/users.py",

        "line_number":
            line_number,

        "proposed_cwe":
            "CWE-89",

        "suggested_severity":
            "HIGH",

        "confidence":
            0.8,

        "chunk_id":
            chunk_id,
    }


def test_pipeline_passes_selected_chunks_to_proposer():
    chunks = [
        make_chunk("1", "aaa"),
        make_chunk("2", "bbb"),
        make_chunk("3", "ccc"),
    ]

    proposer = FakeStaticProposer()

    budget = LLMExecutionBudget(
        max_chunks=2,
        max_source_chars=100,
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            chunks
        ),
        proposer=proposer,
        budget=budget,
    )

    assert len(
        proposer.calls
    ) == 1

    assert (
        proposer.calls[0]["chunks"]
        == chunks[:2]
    )

    assert (
        result["llm_execution"][
            "chunks_received"
        ]
        == 3
    )

    assert (
        result["llm_execution"][
            "chunks_selected"
        ]
        == 2
    )

    assert (
        result["llm_execution"][
            "chunks_skipped"
        ]
        == 1
    )

    assert (
        result["llm_execution"][
            "provider"
        ]
        == "FAKE"
    )


def test_pipeline_preserves_application_name():
    chunks = [
        make_chunk("1")
    ]

    proposer = FakeStaticProposer()

    run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            chunks
        ),
        proposer=proposer,
    )

    assert (
        proposer.calls[0][
            "application_name"
        ]
        == "Generic Application"
    )


def test_pipeline_returns_aggregated_findings():
    first = make_proposal(
        line_number=10,
        chunk_id="chunk-1",
    )

    duplicate = make_proposal(
        line_number=11,
        chunk_id="chunk-2",
    )

    proposer = FakeStaticProposer(
        proposals=[
            first,
            duplicate,
        ]
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [
                make_chunk("chunk-1"),
                make_chunk("chunk-2"),
            ]
        ),
        proposer=proposer,
    )

    assert len(
        result["findings"]
    ) == 1

    assert (
        result["aggregation"][
            "proposals_received"
        ]
        == 2
    )

    assert (
        result["aggregation"][
            "proposals_retained"
        ]
        == 1
    )

    assert (
        result["aggregation"][
            "duplicates_merged"
        ]
        == 1
    )

    assert set(
        result["findings"][0][
            "observed_in_chunks"
        ]
    ) == {
        "chunk-1",
        "chunk-2",
    }


def test_pipeline_does_not_modify_original_analysis():
    original = make_analysis(
        [
            make_chunk("1")
        ]
    )

    proposer = FakeStaticProposer(
        proposals=[
            make_proposal()
        ]
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=original,
        proposer=proposer,
    )

    assert original["findings"] == []

    assert (
        "llm_execution"
        not in original
    )

    assert result is not original


def test_pipeline_handles_empty_context():
    proposer = FakeStaticProposer()

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(),
        proposer=proposer,
    )

    assert (
        proposer.calls[0]["chunks"]
        == []
    )

    assert result["findings"] == []

    assert (
        result["llm_execution"][
            "chunks_received"
        ]
        == 0
    )

    assert (
        result["llm_execution"][
            "chunks_selected"
        ]
        == 0
    )


def test_pipeline_rejects_invalid_analysis():
    with pytest.raises(
        TypeError,
        match="prepared_analysis",
    ):
        run_static_proposal_pipeline(
            prepared_analysis=[],
            proposer=FakeStaticProposer(),
        )


def test_pipeline_rejects_invalid_source_context():
    analysis = make_analysis()

    analysis[
        "source_context"
    ] = "not-a-list"

    with pytest.raises(
        ValueError,
        match="source_context",
    ):
        run_static_proposal_pipeline(
            prepared_analysis=analysis,
            proposer=FakeStaticProposer(),
        )


class InvalidReturnProposer(
    StaticProposer
):
    provider_name = "INVALID"

    def propose(
        self,
        *,
        application_name,
        chunks,
    ):
        return {
            "not": "a list"
        }


def test_pipeline_rejects_invalid_proposer_return():
    with pytest.raises(
        TypeError,
        match=(
            "Static proposer must return a list"
        ),
    ):
        run_static_proposal_pipeline(
            prepared_analysis=(
                make_analysis(
                    [make_chunk("1")]
                )
            ),
            proposer=(
                InvalidReturnProposer()
            ),
        )


def test_pipeline_supports_noop_provider():
    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [make_chunk("1")]
        ),
        provider_name="none",
    )

    assert result["findings"] == []

    assert (
        result["proposal_provider"]
        == "NONE"
    )

    assert (
        result["llm_execution"][
            "provider"
        ]
        == "NONE"
    )


def test_pipeline_records_character_budget():
    chunks = [
        make_chunk("1", "aaaa"),
        make_chunk("2", "bbbb"),
        make_chunk("3", "cccc"),
    ]

    proposer = FakeStaticProposer()

    budget = LLMExecutionBudget(
        max_chunks=100,
        max_source_chars=8,
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            chunks
        ),
        proposer=proposer,
        budget=budget,
    )

    execution = result[
        "llm_execution"
    ]

    assert (
        execution[
            "source_chars_received"
        ]
        == 12
    )

    assert (
        execution[
            "source_chars_selected"
        ]
        == 8
    )

    assert (
        execution["truncated"]
        is True
    )


class ReportingStaticProposer(
    FakeStaticProposer
):
    provider_name = "REPORTING_FAKE"

    def __init__(
        self,
        proposals=None,
        execution_report=None,
    ):
        super().__init__(
            proposals=proposals
        )

        self.last_execution_report = (
            execution_report
            if execution_report is not None
            else {
                "chunks_attempted": 0,
                "chunks_succeeded": 0,
                "chunks_failed": 0,
                "failed_chunks": [],
            }
        )


def test_pipeline_includes_optional_proposer_execution_report():
    proposer = ReportingStaticProposer(
        execution_report={
            "chunks_attempted": 2,
            "chunks_succeeded": 1,
            "chunks_failed": 1,
            "failed_chunks": [
                {
                    "chunk_id": "2",
                    "source_file": "app/example.py",
                    "status_code": 503,
                    "error_type": "ServerError",
                    "error": "temporary outage",
                }
            ],
        }
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [
                make_chunk("1"),
                make_chunk("2"),
            ]
        ),
        proposer=proposer,
    )

    execution = result["llm_execution"]

    assert execution["provider"] == "REPORTING_FAKE"
    assert execution["chunks_attempted"] == 2
    assert execution["chunks_succeeded"] == 1
    assert execution["chunks_failed"] == 1
    assert execution["failed_chunks"][0]["chunk_id"] == "2"
    assert execution["failed_chunks"][0]["status_code"] == 503


def test_pipeline_remains_compatible_without_execution_report():
    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [make_chunk("1")]
        ),
        proposer=FakeStaticProposer(),
    )

    execution = result["llm_execution"]

    assert execution["provider"] == "FAKE"
    assert "chunks_attempted" not in execution
    assert "chunks_succeeded" not in execution
    assert "chunks_failed" not in execution
    assert "failed_chunks" not in execution


def test_pipeline_copies_failed_chunk_metadata():
    failed_chunks = [
        {
            "chunk_id": "1",
            "source_file": "app/example.py",
            "status_code": 503,
            "error_type": "ServerError",
            "error": "temporary outage",
        }
    ]

    proposer = ReportingStaticProposer(
        execution_report={
            "chunks_attempted": 1,
            "chunks_succeeded": 0,
            "chunks_failed": 1,
            "failed_chunks": failed_chunks,
        }
    )

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [make_chunk("1")]
        ),
        proposer=proposer,
    )

    returned = result["llm_execution"]["failed_chunks"]

    assert returned == failed_chunks
    assert returned is not failed_chunks
    assert returned[0] is not failed_chunks[0]

    returned[0]["error"] = "changed"

    assert failed_chunks[0]["error"] == "temporary outage"


def test_pipeline_ignores_invalid_optional_execution_report():
    proposer = FakeStaticProposer()
    proposer.last_execution_report = "not-a-dictionary"

    result = run_static_proposal_pipeline(
        prepared_analysis=make_analysis(
            [make_chunk("1")]
        ),
        proposer=proposer,
    )

    execution = result["llm_execution"]

    assert execution["provider"] == "FAKE"
    assert "chunks_attempted" not in execution
