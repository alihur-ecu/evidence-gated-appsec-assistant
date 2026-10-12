"""Web coverage: scan list and the opt-in archive action."""
from __future__ import annotations

import json

from app.web import server


def _configure(monkeypatch, tmp_path):
    history = tmp_path / "history"
    reports = tmp_path / "reports"
    history.mkdir()
    reports.mkdir()
    monkeypatch.setattr(server, "SCAN_HISTORY_DIR", history)
    monkeypatch.setattr(server, "SAVED_ANALYSES_DIR", reports)
    monkeypatch.setattr(server, "ANALYSES", {})
    monkeypatch.setattr(server, "ANALYSIS_SESSIONS", {})
    monkeypatch.setattr(server, "FINDINGS", {})
    monkeypatch.setattr(server, "FINDING_METADATA", {})
    monkeypatch.setattr(server, "EVIDENCE_BY_FINDING", {})
    monkeypatch.setattr(server, "REVIEW_BY_FINDING", {})
    monkeypatch.setattr(server, "LATEST_ANALYSIS_ID", None)
    return history, reports


def _snapshot(history, analysis_id, *, completed=None):
    content = {
        "analysis_id": analysis_id,
        "saved_at_utc": "2026-10-12T23:00:00+00:00",
        "analysis": {"analysis_type": "DYNAMIC", "target": "http://localhost:4280/", "proposal_provider": "LMSTUDIO"},
        "findings": [{"finding_id": "F-0001"}],
    }
    if completed:
        content["created_at_utc"] = completed
    (history / f"{analysis_id}.json").write_text(json.dumps(content), encoding="utf-8")


def test_scan_history_list_shows_perth_time_and_actions(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-2026", completed="2026-10-12T16:44:26+00:00")
    response = server.app.test_client().get("/scan-history")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "D-2026" in html
    assert "13 Oct 2026" in html and "12:44 AM AWST" in html
    assert 'type="search"' in html
    assert "/scan-history/D-2026/archive" in html
    assert "Save" not in html or "Saved (legacy)" in html


def test_get_cannot_archive(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-TEST")
    response = server.app.test_client().get("/scan-history/D-TEST/archive")
    assert response.status_code == 405
    assert (history / "D-TEST.json").is_file()


def test_post_without_valid_csrf_cannot_archive(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-TEST")
    response = server.app.test_client().post("/scan-history/D-TEST/archive", data={"archive_token": "wrong"})
    assert response.status_code == 403
    assert (history / "D-TEST.json").is_file()


def test_post_valid_token_archives_selected_only(monkeypatch, tmp_path):
    history, reports = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-TEST")
    _snapshot(history, "D-OTHER")
    (reports / "D-TEST.json").write_text("{}", encoding="utf-8")
    client = server.app.test_client()
    response = client.post("/scan-history/D-TEST/archive", data={"archive_token": server.SCAN_HISTORY_ARCHIVE_TOKEN})
    assert response.status_code == 303
    assert not (history / "D-TEST.json").exists()
    assert not (reports / "D-TEST.json").exists()
    assert (history / "D-OTHER.json").is_file()
    assert (history / ".trash").is_dir()
    content = client.get("/scan-history").get_data(as_text=True)
    assert "D-TEST" not in content
    assert "D-OTHER" in content


def test_save_preserves_initial_completion_time(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(server, "ANALYSES", {"D-TIME": {"analysis_id": "D-TIME", "analysis_type": "DYNAMIC"}})
    server._save_scan_snapshot("D-TIME")
    path = history / "D-TIME.json"
    first = json.loads(path.read_text(encoding="utf-8"))["created_at_utc"]
    server._save_scan_snapshot("D-TIME")
    second = json.loads(path.read_text(encoding="utf-8"))["created_at_utc"]
    assert first == second


def test_unsaved_report_restores_scan_before_report(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-REPORT")
    client = server.app.test_client()
    response = client.get("/scan-history/D-REPORT/report")
    assert response.status_code in {301, 302, 303}
    assert response.headers["Location"].endswith("/analysis/D-REPORT/report")
    assert "D-REPORT" in server.ANALYSES


def test_legacy_completion_is_not_mislabelled_after_new_save(monkeypatch, tmp_path):
    history, _ = _configure(monkeypatch, tmp_path)
    _snapshot(history, "D-LEGACY")
    monkeypatch.setattr(server, "ANALYSES", {"D-LEGACY": {"analysis_id": "D-LEGACY", "analysis_type": "DYNAMIC"}})
    server._save_scan_snapshot("D-LEGACY")
    stored = json.loads((history / "D-LEGACY.json").read_text(encoding="utf-8"))
    assert stored["completed_at_source"] == "LEGACY_SAVED_TIMESTAMP"
    rendered = server.app.test_client().get("/scan-history").get_data(as_text=True)
    assert "Saved (legacy)" in rendered
