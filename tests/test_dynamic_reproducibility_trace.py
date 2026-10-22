

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.dynamic_analysis.context_builder import DynamicContextBuilder
from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint, DiscoveredParameter, DiscoveryResult,
)
from app.dynamic_analysis.target import build_dynamic_target
from app.analysis.proposers.lmstudio import LMStudioStaticProposer
from app.analysis.proposers.context import AnalysisContext
from app.dynamic_analysis.pipeline import DynamicAnalysisPipeline


def discovery_with_endpoints(reverse=False):
    d = DiscoveryResult(target=build_dynamic_target("https://example.test/"))
    endpoints = [
        DiscoveredEndpoint(
            url=f"https://example.test/route-{i}", method="GET",
            parameters=(DiscoveredParameter(name=f"field{i}", location="query"),),
        )
        for i in (1, 2, 3)
    ]
    d.endpoints.extend(reversed(endpoints) if reverse else endpoints)
    return d


def test_selected_manifest_stable_for_reordered_discovery():
    builder = DynamicContextBuilder(max_contexts=2)
    a = builder.build(discovery_with_endpoints())
    b = builder.build(discovery_with_endpoints(reverse=True))
    assert a.contexts_created == 3
    assert a.contexts_selected == 2
    assert len(a.excluded_manifest) == 1
    assert len(a.selected_manifest) == 2
    assert a.selected_content_sha256 == b.selected_content_sha256
    assert a.selected_surface_sha256 == b.selected_surface_sha256
    assert a.to_dict()["coverage"]["excluded_manifest"]
    for entry in a.selected_manifest + a.excluded_manifest:
        assert len(entry["surface_sha256"]) == 64
        assert len(entry["content_sha256"]) == 64
        assert "https://" not in str(entry)


def test_content_fingerprint_changes_when_context_changes():
    d = discovery_with_endpoints()
    builder = DynamicContextBuilder(max_contexts=2)
    a = builder.build(d)
    d2 = deepcopy(d)
    d2.endpoints[0] = DiscoveredEndpoint(
        url="https://example.test/route-1", method="POST",
        parameters=(DiscoveredParameter(name="field1", location="body"),),
    )
    b = builder.build(d2)
    assert a.selected_content_sha256 != b.selected_content_sha256


def test_lmstudio_uses_zero_temperature_by_default(monkeypatch):
    monkeypatch.delenv("LMSTUDIO_TEMPERATURE", raising=False)
    model = LMStudioStaticProposer()
    model.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=Mock(return_value="fake-response"))
    ))
    model._chat_completion_with_retry(prompt="demo", system_instruction="instructions")
    args = model.client.chat.completions.create.call_args.kwargs
    assert args["temperature"] == 0.0
    assert args["max_tokens"] == model.max_output_tokens


def test_lmstudio_rejects_invalid_temperature(monkeypatch):
    monkeypatch.setenv("LMSTUDIO_TEMPERATURE", "2.1")
    with pytest.raises(ValueError, match="TEMPERATURE"):
        LMStudioStaticProposer()


def test_pipeline_execution_report_preserves_nonsecret_metadata():
    class DummyProposer:
        provider_name = "LMSTUDIO"
        last_execution_report = {
            "chunks_attempted": 2, "chunks_succeeded": 1,
            "chunks_failed": 1, "contexts_planned": 3,
            "model": "local-demo", "temperature": 0.0,
            "max_output_tokens": 1024,
            "context_outcomes": [
                {"context_id": "c1", "outcome": "SUCCESS", "finding_count": 1},
                {"context_id": "c2", "outcome": "FAILED", "finding_count": 0},
            ],
            "failed_chunks": [{"context_id": "c2", "error_type": "Timeout",
                               "status_code": 503, "error": "secret-token"}],
        }
    pipeline = DynamicAnalysisPipeline(proposer=DummyProposer())
    result = pipeline._proposal_execution_report()
    assert result["contexts_unattempted"] == 1
    assert result["temperature"] == 0.0
    assert result["context_outcomes"][0]["finding_count"] == 1
    assert "secret-token" not in str(result)


def test_web_adapter_persists_dynamic_proposal_metadata():
    pytest.importorskip("flask")
    from app.web.server import prepare_dynamic_analysis_result
    result = prepare_dynamic_analysis_result({
        "target": {"base_url": "http://localhost:4280/"},
        "proposals": [], "proposal_provider": "LMSTUDIO",
        "proposal_status": "PARTIAL",
        "proposal_execution": {"chunks_attempted": 12,
                               "chunks_succeeded": 7, "chunks_failed": 5},
        "context_build": {"coverage": {"contexts_selected": 12,
                                          "selected_content_sha256": "a"*64}},
    }, application_name="DVWA", analysis_scope="local-lab")
    assert result["proposal_status"] == "PARTIAL"
    assert result["proposal_execution"]["chunks_failed"] == 5
    assert result["context_build"]["coverage"]["selected_content_sha256"] == "a"*64
    assert result["findings"] == []


def test_lmstudio_records_per_context_counts_without_external_requests(monkeypatch):
    monkeypatch.delenv("LMSTUDIO_TEMPERATURE", raising=False)
    model = LMStudioStaticProposer()
    model._analyse_context = Mock(side_effect=[
        [{"finding_type": "SQL_INJECTION", "explanation": "candidate"}],
        [],
    ])
    contexts = [
        AnalysisContext(context_id="one", scan_type="DYNAMIC", content="first"),
        AnalysisContext(context_id="two", scan_type="DYNAMIC", content="second"),
    ]
    proposals = model.propose_contexts(application_name="Demo", contexts=contexts)
    report = model.last_execution_report
    assert len(proposals) == 1
    assert report["chunks_attempted"] == 2
    assert report["chunks_succeeded"] == 2
    assert report["chunks_failed"] == 0
    assert report["contexts_planned"] == 2
    assert report["context_outcomes"] == [
        {"context_id": "one", "outcome": "SUCCESS", "finding_count": 1},
        {"context_id": "two", "outcome": "SUCCESS", "finding_count": 0},
    ]
