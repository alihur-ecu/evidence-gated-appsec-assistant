"""Prevent a history-only script from replacing the shared application JS.

These are contract checks over the real web assets. They intentionally do not
require a running Flask server, a browser, or an authorised scan target.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "web" / "templates"
JS = ROOT / "app" / "web" / "static" / "js"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_shared_javascript_restores_both_analysis_modes():
    home = _read(TEMPLATES / "home.html")
    base = _read(TEMPLATES / "base.html")
    shared = _read(JS / "app.js")

    assert "js/app.js" in base
    assert 'id="analysisLaunch"' in home
    assert 'data-analysis-mode="static"' in home
    assert 'data-analysis-mode="dynamic"' in home
    assert 'getElementById(' in shared
    assert '"analysisLaunch"' in shared
    assert '"analysisConfigPanel"' in shared
    assert '"staticConfig"' in shared
    assert '"dynamicConfig"' in shared
    assert '"startAnalysisButton"' in shared
    assert "selectMode(" in shared
    assert 'card.addEventListener(' in shared


def test_static_and_dynamic_jobs_keep_their_original_endpoints():
    script = _read(JS / "app.js")
    server = _read(ROOT / "app" / "web" / "server.py")

    for endpoint in ("/analysis/static/job", "/analysis/dynamic/job"):
        assert endpoint in script
        assert endpoint in server

    # Retain evidence and human-review browser workflow.
    assert '"runVerificationButton"' in script
    assert '"final_severity"' in script
    assert '"ACCEPTED"' in script
    assert '"REJECTED"' in script


def test_scan_history_uses_a_separate_script():
    history_html = _read(TEMPLATES / "scan_history.html")
    history_js = _read(JS / "scan_history.js")
    shared_js = _read(JS / "app.js")

    assert "js/scan_history.js" in history_html
    assert (JS / "scan_history.js").is_file()
    assert '"scanHistorySearch"' in history_js
    assert '"scanHistoryCount"' in history_js
    assert '"scanHistoryNoMatches"' in history_js
    assert '.history-archive-form' in history_js
    assert 'window.confirm(' in history_js
    assert '"scanHistorySearch"' not in shared_js


def test_javascript_parses_if_node_is_installed():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is optional; syntax checked separately when available")

    for name in ("app.js", "scan_history.js"):
        result = subprocess.run(
            [node, "--check", str(JS / name)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{name}: {result.stderr}"
