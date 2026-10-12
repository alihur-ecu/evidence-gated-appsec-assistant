"""Flask integration: static candidates -> evidence -> gated human review.

Runs in the project's .venv. This module requires Flask, but never sends
external HTTP requests or invokes a local LLM.
"""
import pytest
pytest.importorskip("flask")

from app.analysis.static_pipeline import run_static_proposal_pipeline
from app.analysis.proposers.base import StaticProposer
from app.analysis.providers.static_source_provider import run_static_source_analysis
from app.web import server


class EmptyStaticProposer(StaticProposer):
    provider_name = "TEST"

    def propose(self, *, application_name, chunks):
        return []


def test_static_web_oracle_collects_real_source_evidence_and_then_review(tmp_path, monkeypatch):
    from zipfile import ZipFile
    source_zip = tmp_path / "app.zip"
    with ZipFile(source_zip, "w") as arc:
        arc.writestr("sample/app.py", '''from flask import Flask, request
app = Flask(__name__)
@app.route("/products")
def products():
    item = request.args.get("id", "1")
    sql = "SELECT * FROM products WHERE id=" + item
    return db.execute(sql)
''')
    prepared = run_static_source_analysis(source_path=str(source_zip),
        original_filename=source_zip.name, application_name="Test Website")
    analysis = run_static_proposal_pipeline(prepared_analysis=prepared,
        proposer=EmptyStaticProposer())
    analysis["analysis_id"] = "A-STATIC-REGRESSION"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server, "_save_scan_snapshot", lambda analysis_id: None)
    previous = (server.FINDINGS.copy(), server.FINDING_METADATA.copy(),
                server.EVIDENCE_BY_FINDING.copy(), server.REVIEW_BY_FINDING.copy(),
                server.ANALYSES.copy())
    try:
        server.register_analysis_result(analysis)
        finding = next(iter(server.FINDINGS.values()))
        client = server.app.test_client()
        detail = client.get(f"/findings/{finding.finding_id}")
        assert detail.status_code == 200
        assert b"Source-Pattern Proposed Finding" in detail.data
        assert b"STATIC_SOURCE_PATTERN" in detail.data
        assert client.post(f"/findings/{finding.finding_id}/review",
                           json={"field":"human_decision", "value":"ACCEPTED"}).status_code == 409
        verified = client.post(f"/findings/{finding.finding_id}/verify")
        assert verified.status_code == 200, verified.get_json()
        assert verified.get_json()["verification_status"] == "COMPLETED"
        assert finding.finding_id in server.EVIDENCE_BY_FINDING
        assert server.EVIDENCE_BY_FINDING[finding.finding_id]["observations"]
        assert client.post(f"/findings/{finding.finding_id}/review",
                           json={"field":"human_decision", "value":"NEEDS_FURTHER_REVIEW"}).status_code == 200
        verified_detail = client.get(f"/findings/{finding.finding_id}")
        assert b"Source observations and retained code excerpts" in verified_detail.data
    finally:
        for store, contents in zip(
            (server.FINDINGS, server.FINDING_METADATA, server.EVIDENCE_BY_FINDING,
             server.REVIEW_BY_FINDING, server.ANALYSES), previous
        ):
            store.clear()
            store.update(contents)
