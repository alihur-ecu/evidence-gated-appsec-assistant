from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import re
import uuid


_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_AWST = timezone(timedelta(hours=8), "AWST")  # Perth: UTC+8, no daylight saving


def display_awst_timestamp(value: str | None) -> str:
    """Display stored UTC time in Perth time, or an honest unknown marker."""
    if not isinstance(value, str) or not value.strip():
        return "Time unavailable"
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if when.tzinfo is None:
            return "Time unavailable"
        return when.astimezone(_AWST).strftime("%d %b %Y · %I:%M %p AWST")
    except (ValueError, OverflowError):
        return "Time unavailable"


def archive_saved_scan(*, analysis_id: str, scan_history_dir: Path,
                       saved_analyses_dir: Path) -> bool:
  
    if not isinstance(analysis_id, str) or not _ID.fullmatch(analysis_id):
        raise ValueError("Invalid analysis ID")

    history_dir = Path(scan_history_dir)
    report_dir = Path(saved_analyses_dir)
    source = history_dir / f"{analysis_id}.json"
    report = report_dir / f"{analysis_id}.json"

    # A symlink must not be followed as a substitute for a real saved scan.
    if source.is_symlink() or not source.is_file():
        return False
    try:
        snapshot = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid snapshot") from exc
    if not isinstance(snapshot, dict) or snapshot.get("analysis_id") != analysis_id:
        raise ValueError("Snapshot ID does not match filename")
    if report.is_symlink():
        raise ValueError("Unsafe linked report")

    trash = history_dir / ".trash" / f"{analysis_id}-{uuid.uuid4().hex[:12]}"
    trash.mkdir(parents=True, exist_ok=False)
    moved_report = False
    try:
        if report.is_file():
            report.replace(trash / "saved_report.json")
            moved_report = True
        source.replace(trash / "scan_snapshot.json")
    except OSError:
        if moved_report:
            (trash / "saved_report.json").replace(report)
        raise
    return True
