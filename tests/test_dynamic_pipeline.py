from app.dynamic_analysis.context_builder import (
    DynamicContextBuilder,
)
from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveryResult,
)
from app.dynamic_analysis.pipeline import (
    DynamicAnalysisPipeline,
    run_dynamic_analysis,
)
from app.dynamic_analysis.target import (
    build_dynamic_target,
)


class FakeDiscovery:
    def __init__(self):
        self.received_target = None

    def discover(self, target):
        self.received_target = target

        result = DiscoveryResult(
            target=target,
        )

        result.endpoints.append(
            DiscoveredEndpoint(
                url=(
                    target.origin
                    + "/search?q=test"
                ),
                method="GET",
                parameters=(
                    DiscoveredParameter(
                        name="q",
                        location="query",
                        input_type=None,
                    ),
                ),
            )
        )

        return result


class FakeProposer:
    provider_name = "TEST"

    def __init__(self):
        self.application_name = None
        self.contexts = None

    def propose_contexts(
        self,
        *,
        application_name,
        contexts,
    ):
        self.application_name = application_name
        self.contexts = contexts

        if not contexts:
            return []

        context = contexts[0]

        return [
            {
                "finding_type":
                    "Candidate test finding",
                "explanation":
                    "Test proposal only.",
                "scan_type":
                    context.scan_type,
                "endpoint":
                    context.metadata.get(
                        "endpoint_url"
                    ),
                "method":
                    context.metadata.get(
                        "method"
                    ),
                "proposed_cwe":
                    None,
                "suggested_severity":
                    None,
                "confidence":
                    0.5,
                "proposal_source":
                    "TEST",
                "context_id":
                    context.context_id,
            }
        ]


class FailedProposer:
    provider_name = "TEST"

    def __init__(self):
        self.last_execution_report = {}

    def propose_contexts(self, *, application_name, contexts):
        self.last_execution_report = {
            "chunks_attempted": 1,
            "chunks_succeeded": 0,
            "chunks_failed": 1,
            "failed_chunks": [
                {"status_code": 429, "error_type": "RateLimitError"}
            ],
        }
        return []


class InvalidProposer:
    provider_name = "INVALID"


class BadReturnProposer:
    provider_name = "BAD"

    def propose_contexts(
        self,
        *,
        application_name,
        contexts,
    ):
        return {
            "not": "a list"
        }


def make_pipeline(proposer=None):
    return DynamicAnalysisPipeline(
        discovery=FakeDiscovery(),
        context_builder=DynamicContextBuilder(),
        proposer=(
            proposer
            if proposer is not None
            else FakeProposer()
        ),
    )


def test_pipeline_runs_end_to_end_with_injected_dependencies():
    discovery = FakeDiscovery()
    proposer = FakeProposer()

    pipeline = DynamicAnalysisPipeline(
        discovery=discovery,
        context_builder=DynamicContextBuilder(),
        proposer=proposer,
    )

    result = pipeline.run(
        target_url="https://example.test",
        application_name="Example Application",
    )

    assert result.target["scheme"] == "https"
    assert result.target["hostname"] == "example.test"
    assert result.proposal_provider == "TEST"
    assert len(result.proposals) == 1

    assert (
        result.proposals[0]["scan_type"]
        == "DYNAMIC"
    )


def test_pipeline_passes_analysis_contexts_to_proposer():
    proposer = FakeProposer()

    pipeline = make_pipeline(
        proposer=proposer
    )

    pipeline.run(
        target_url="https://example.test",
        application_name="Example Application",
    )

    assert proposer.contexts

    context = proposer.contexts[0]

    assert context.scan_type == "DYNAMIC"

    assert context.context_id.startswith(
        "dynamic-"
    )


def test_pipeline_preserves_application_name():
    proposer = FakeProposer()

    pipeline = make_pipeline(
        proposer=proposer
    )

    pipeline.run(
        target_url="https://example.test",
        application_name="Generic Banking Portal",
    )

    assert (
        proposer.application_name
        == "Generic Banking Portal"
    )


def test_pipeline_does_not_require_known_application():
    pipeline = make_pipeline()

    result = pipeline.run(
        target_url=(
            "https://unknown-app.test/custom/path"
        ),
        application_name=(
            "Unknown Custom Application"
        ),
    )

    assert (
        result.target["hostname"]
        == "unknown-app.test"
    )

    assert (
        result.target["start_path"]
        == "/custom/path"
    )


def test_pipeline_rejects_empty_application_name():
    pipeline = make_pipeline()

    try:
        pipeline.run(
            target_url="https://example.test",
            application_name="   ",
        )

    except ValueError as exc:
        assert "application_name" in str(exc)

    else:
        raise AssertionError(
            "Expected ValueError."
        )


def test_pipeline_rejects_non_string_application_name():
    pipeline = make_pipeline()

    try:
        pipeline.run(
            target_url="https://example.test",
            application_name=123,
        )

    except TypeError as exc:
        assert "application_name" in str(exc)

    else:
        raise AssertionError(
            "Expected TypeError."
        )


def test_pipeline_requires_generic_context_provider():
    pipeline = make_pipeline(
        proposer=InvalidProposer()
    )

    try:
        pipeline.run(
            target_url="https://example.test",
            application_name="Example Application",
        )

    except TypeError as exc:
        assert "propose_contexts" in str(exc)

    else:
        raise AssertionError(
            "Expected TypeError."
        )


def test_pipeline_rejects_invalid_provider_return_type():
    pipeline = make_pipeline(
        proposer=BadReturnProposer()
    )

    try:
        pipeline.run(
            target_url="https://example.test",
            application_name="Example Application",
        )

    except TypeError as exc:
        assert "must return a list" in str(exc)

    else:
        raise AssertionError(
            "Expected TypeError."
        )


def test_convenience_function_returns_dictionary():
    result = run_dynamic_analysis(
        target_url="https://example.test",
        application_name="Example Application",
        discovery=FakeDiscovery(),
        context_builder=DynamicContextBuilder(),
        proposer=FakeProposer(),
    )

    assert isinstance(result, dict)

    assert (
        result["proposal_provider"]
        == "TEST"
    )

    assert isinstance(
        result["proposals"],
        list,
    )


def test_pipeline_result_contains_coverage_information():
    result = run_dynamic_analysis(
        target_url="https://example.test",
        application_name="Example Application",
        discovery=FakeDiscovery(),
        context_builder=DynamicContextBuilder(),
        proposer=FakeProposer(),
    )

    coverage = result[
        "context_build"
    ]["coverage"]

    assert (
        coverage["contexts_created"]
        >= 1
    )

    assert (
        coverage["contexts_selected"]
        >= 1
    )

    assert coverage["truncated"] is False


def test_pipeline_target_is_built_by_generic_target_layer():
    expected = build_dynamic_target(
        "https://example.test/app"
    )

    discovery = FakeDiscovery()

    pipeline = DynamicAnalysisPipeline(
        discovery=discovery,
        context_builder=DynamicContextBuilder(),
        proposer=FakeProposer(),
    )

    pipeline.run(
        target_url="https://example.test/app",
        application_name="Example Application",
    )

    assert discovery.received_target == expected


def test_candidate_is_not_automatically_verified():
    result = run_dynamic_analysis(
        target_url="https://example.test",
        application_name="Example Application",
        discovery=FakeDiscovery(),
        context_builder=DynamicContextBuilder(),
        proposer=FakeProposer(),
    )

    finding = result["proposals"][0]

    assert "verification_status" not in finding
    assert "oracle_result" not in finding
    assert "human_decision" not in finding


def test_pipeline_marks_total_proposal_failure_explicitly():
    result = make_pipeline(FailedProposer()).run(
        target_url="https://example.test/",
        application_name="Example",
    )

    assert result.proposals == []
    assert result.proposal_status == "FAILED"
    assert result.proposal_execution["chunks_failed"] == 1
    assert result.proposal_execution["chunks_succeeded"] == 0

