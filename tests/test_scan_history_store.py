"""Offline, side-effect isolated tests for the safer Scan History archive."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from app.web.scan_history_store import archive_saved_scan, display_awst_timestamp


def _store(tmp_path: Path, analysis_id: str, report: bool = True):
    history = tmp_path / "scan_history"
    reports = tmp_path / "saved_analyses"
    history.mkdir(exist_ok=True)
    reports.mkdir(exist_ok=True)
    (history / f"{analysis_id}.json").write_text(
        json.dumps({"analysis_id": analysis_id, "analysis": {"target": "http://localhost/"},
                    "evidence_by_finding": {"F-1": {"decision": "PROVED"}}}), encoding="utf-8")
    if report:
        (reports / f"{analysis_id}.json").write_text(json.dumps({"analysis_id": analysis_id}), encoding="utf-8")
    return history, reports


def test_awst_conversion_and_legacy_format():
    assert display_awst_timestamp("2026-10-12T16:44:26+00:00") == "13 Oct 2026 · 12:44 AM AWST"
    assert display_awst_timestamp("2026-10-12T16:44:26Z") == "13 Oct 2026 · 12:44 AM AWST"
    assert display_awst_timestamp("2026-10-12T16:44:26") == "Time unavailable"
    assert display_awst_timestamp("not-a-date") == "Time unavailable"
    assert display_awst_timestamp(None) == "Time unavailable"


def test_archive_moves_only_selected_snapshot_and_its_report(tmp_path):
    history, reports = _store(tmp_path, "D-FIRST")
    _store(tmp_path, "D-SECOND")
    other = tmp_path / "external_evidence.json"
    other.write_text('{"keep": true}', encoding="utf-8")

    assert archive_saved_scan(analysis_id="D-FIRST", scan_history_dir=history, saved_analyses_dir=reports)
    assert not (history / "D-FIRST.json").exists()
    assert not (reports / "D-FIRST.json").exists()
    assert (history / "D-SECOND.json").is_file()
    assert (reports / "D-SECOND.json").is_file()
    assert other.read_text(encoding="utf-8") == '{"keep": true}'
    archived = list((history / ".trash").glob("D-FIRST-*/scan_snapshot.json"))
    assert len(archived) == 1
    saved = json.loads(archived[0].read_text(encoding="utf-8"))
    assert saved["evidence_by_finding"]["F-1"]["decision"] == "PROVED"
    assert (archived[0].parent / "saved_report.json").exists()


def test_archive_without_saved_report(tmp_path):
    history, reports = _store(tmp_path, "A-ONLY", report=False)
    assert archive_saved_scan(analysis_id="A-ONLY", scan_history_dir=history, saved_analyses_dir=reports)
    assert len(list((history / ".trash").glob("A-ONLY-*/scan_snapshot.json"))) == 1


def test_unknown_analysis_does_not_make_trash_or_delete_anything(tmp_path):
    history, reports = _store(tmp_path, "D-KNOWN")
    assert archive_saved_scan(analysis_id="D-UNKNOWN", scan_history_dir=history, saved_analyses_dir=reports) is False
    assert (history / "D-KNOWN.json").is_file()
    assert not (history / ".trash").exists()


@pytest.mark.parametrize("bad_id", ["../outside", "D-ID/../../other", "", "D-X\\other", ".hidden", "D-%2F"])
def test_rejects_invalid_ids_without_changes(tmp_path, bad_id):
    history, reports = _store(tmp_path, "D-KNOWN")
    with pytest.raises(ValueError):
        archive_saved_scan(analysis_id=bad_id, scan_history_dir=history, saved_analyses_dir=reports)
    assert (history / "D-KNOWN.json").exists()


def test_refuses_corrupted_or_mismatched_snapshots(tmp_path):
    history, reports = _store(tmp_path, "D-MATCH")
    (history / "D-MATCH.json").write_text(json.dumps({"analysis_id": "D-DIFFERENT"}), encoding="utf-8")
    with pytest.raises(ValueError):
        archive_saved_scan(analysis_id="D-MATCH", scan_history_dir=history, saved_analyses_dir=reports)
    assert (history / "D-MATCH.json").is_file()
    assert (reports / "D-MATCH.json").is_file()


def test_recovery_preserves_files_in_trash(tmp_path):
    history, reports = _store(tmp_path, "D-RESTORE")
    archive_saved_scan(analysis_id="D-RESTORE", scan_history_dir=history, saved_analyses_dir=reports)
    archived = next((history / ".trash").glob("D-RESTORE-*"))
    (archived / "scan_snapshot.json").replace(history / "D-RESTORE.json")
    (archived / "saved_report.json").replace(reports / "D-RESTORE.json")
    assert (history / "D-RESTORE.json").is_file()
    assert (reports / "D-RESTORE.json").is_file()
