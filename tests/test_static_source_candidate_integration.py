"""Regression cases for static scan candidates and evidence boundaries.

No live model, network, Flask, or external fixture is needed.
"""
from pathlib import Path
from zipfile import ZipFile

from app.analysis.finding_adapter import adapt_analysis_result
from app.analysis.proposers.base import StaticProposer
from app.analysis.providers.static_source_provider import run_static_source_analysis
from app.analysis.static_pipeline import run_static_proposal_pipeline
from app.models.finding import Finding, FindingStatus, FindingType, ScanType
from app.static_verification_service import StaticVerificationService


UNSAFE_AND_SAFE = '''from flask import Flask, request, render_template_string, render_template
app = Flask(__name__)
@app.route("/product")
def product():
    product_id = request.args.get("id", "1")
    query = "SELECT * FROM products WHERE id=" + product_id
    return db.execute(query)
@app.route("/orders")
def orders():
    status = request.args.get("status", "OPEN")
    query = f"SELECT * FROM orders WHERE status='{status}'"
    return db.execute(query)
@app.route("/safe/product")
def safe_product():
    product_id = request.args.get("id", "1")
    return db.execute("SELECT * FROM products WHERE id=?", (product_id,))
@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    markup = "<b>%s</b>" % text
    return render_template_string(markup)
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "Anonymous")
    return render_template("welcome.html", name=name)
'''
WELCOME = '<h1>{{ name | safe }}</h1>'


class NoLLMFindings(StaticProposer):
    provider_name = "TEST"

    def propose(self, *, application_name, chunks):
        return []


def prepared_fixture(tmp_path):
    path = tmp_path / "source.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("app/main.py", UNSAFE_AND_SAFE)
        archive.writestr("app/templates/welcome.html", WELCOME)
    return run_static_source_analysis(
        source_path=str(path), original_filename=path.name,
        application_name="example static test fixture",
    )


def test_source_patterns_grounded_and_safe_sql_not_reported(tmp_path):
    result = prepared_fixture(tmp_path)
    proposals = result["source_pattern_proposals"]
    assert len(proposals) == 4
    assert {p["endpoint"] for p in proposals} == {
        "/product", "/orders", "/comment", "/welcome"
    }
    assert not any("/safe/product" == p["endpoint"] for p in proposals)
    assert {(p["endpoint"], p["proposed_cwe"]) for p in proposals} == {
        ("/product", "CWE-89"), ("/orders", "CWE-89"),
        ("/comment", "CWE-79"), ("/welcome", "CWE-79"),
    }
    for candidate in proposals:
        assert candidate["source_file"] == "app/main.py"
        assert isinstance(candidate["line_number"], int)
        assert candidate["proposal_source"] == "STATIC_SOURCE_PATTERN"
        assert candidate["observed_in_chunks"]
        assert candidate["scan_type"] == "STATIC"
        assert candidate.get("status") is None


def test_empty_llm_does_not_erase_source_candidates(tmp_path):
    result = run_static_proposal_pipeline(
        prepared_analysis=prepared_fixture(tmp_path), proposer=NoLLMFindings()
    )
    assert len(result["findings"]) == 4
    assert result["proposal_origins"]["source_pattern_proposals_received"] == 4
    assert result["proposal_origins"]["llm_proposals_received"] == 0
    assert all(item["proposal_source"] == "STATIC_SOURCE_PATTERN"
               for item in result["findings"])
    result["analysis_id"] = "A-TEST"
    adapted = adapt_analysis_result(result)
    assert len(adapted) == 4
    assert all(f.status is FindingStatus.PROPOSED for f, _ in adapted)
    assert all(m["proposal_source"] == "STATIC_SOURCE_PATTERN" for _, m in adapted)
    assert all(m.get("source_scope") for _, m in adapted)


def test_source_oracle_scoped_and_xss_requires_human(tmp_path):
    result = run_static_proposal_pipeline(
        prepared_analysis=prepared_fixture(tmp_path), proposer=NoLLMFindings()
    )
    findings = adapt_analysis_result(result)
    verdicts = {}
    for finding, metadata in findings:
        outcome = StaticVerificationService().verify(
            finding, analysis_result=result, metadata=metadata
        )
        verdicts[finding.endpoint] = outcome
        assert outcome.evidence["execution_status"] == "COMPLETED"
        assert outcome.evidence["observations"]
    assert verdicts["/product"].finding_status is FindingStatus.PROVED
    assert verdicts["/orders"].finding_status is FindingStatus.PROVED
    assert verdicts["/comment"].finding_status is FindingStatus.NEEDS_HUMAN
    assert verdicts["/welcome"].finding_status is FindingStatus.NEEDS_HUMAN
    assert verdicts["/welcome"].evidence["signals"]["html_output_observed"] is True


def test_safe_function_does_not_borrow_unsafe_sql_from_other_routes(tmp_path):
    result = run_static_proposal_pipeline(
        prepared_analysis=prepared_fixture(tmp_path), proposer=NoLLMFindings()
    )
    source = UNSAFE_AND_SAFE.splitlines()
    start = next(i for i,line in enumerate(source, 1) if 'def safe_product' in line)
    end = next(i for i,line in enumerate(source, 1) if '@app.route("/comment")' in line)-1
    proposed = Finding(
        finding_type=FindingType.SQL_INJECTION, scan_type=ScanType.STATIC,
        source_file="app/main.py", endpoint="/safe/product", parameter="id",
        explanation="Deliberate negative control"
    )
    observation = StaticVerificationService().verify(
        proposed, analysis_result=result,
        metadata={
            "source_file":"app/main.py", "proposal_source":"STATIC_SOURCE_PATTERN",
            "source_scope": [start, end],
            "observed_in_chunks": [c["chunk_id"] for c in result["source_context"]
                                   if c["source_file"] == "app/main.py"],
        }
    )
    assert observation.finding_status is FindingStatus.NEEDS_HUMAN
    assert observation.evidence["signals"]["unsafe_query_composition_observed"] is False
    assert observation.evidence["signals"]["parameterized_query_observed"] is True


def test_larger_python_file_is_bounded_for_llm(tmp_path):
    path = tmp_path / "large.zip"
    with ZipFile(path,"w") as archive:
        archive.writestr("app/source.py", "def example():\n    return 1\n" * 700)
    result = run_static_source_analysis(source_path=str(path),
                                        original_filename=path.name,
                                        application_name="example")
    assert result["context_coverage"]["chunks_created"] > 1
    assert all(chunk["char_count"] <= 3000 for chunk in result["source_context"])
    assert not result["context_coverage"]["truncated"]


class AllChunksFailed(StaticProposer):
    provider_name = "TEST_FAILING_LLM"
    last_execution_report = {
        "chunks_attempted": 2, "chunks_succeeded": 0, "chunks_failed": 2,
        "failed_chunks": [{"chunk_id": "one"}, {"chunk_id": "two"}],
        "model": "local-test-model", "temperature": 0.0,
        "max_output_tokens": 4096,
    }

    def propose(self, *, application_name, chunks):
        return []


def test_llm_failure_does_not_claim_complete_scan_with_source_patterns(tmp_path):
    result = run_static_proposal_pipeline(
        prepared_analysis=prepared_fixture(tmp_path), proposer=AllChunksFailed()
    )
    assert result["proposal_status"] == "PARTIAL"
    assert result["llm_execution"]["chunks_failed"] == 2
    assert result["llm_execution"]["model"] == "local-test-model"
    assert len(result["findings"]) == 4


def test_static_without_source_patterns_preserves_existing_provider_behaviour():
    result = run_static_proposal_pipeline(
        prepared_analysis={
            "application_name": "unrelated app", "scan_type": "STATIC",
            "source_context": [{
                "chunk_id": "one", "source_file": "script.php",
                "source_code": "<?php echo 'ok';", "char_count": 17,
                "start_line": 1, "end_line": 1,
            }],
        }, proposer=NoLLMFindings()
    )
    assert result["findings"] == []
    assert result["proposal_status"] == "SUCCESS"
