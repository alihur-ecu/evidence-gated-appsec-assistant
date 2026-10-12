"""Regression: the real Flask analysis results HTML must render CWE labels, not OTHER.

This specifically covers the missing integration point between helper tests and the UI.
No external HTTP requests and no Oracle or LLM calls.
"""

from __future__ import annotations

import pytest

from app.models.finding import Finding, FindingStatus, FindingType, ScanType
from app.web import server

CWE_LABELS = [
    ('CWE-434', 'Potential Unrestricted File Upload'),
    ('CWE-307', 'Potential Authentication Rate-Limiting Weakness'),
    ('CWE-352', 'Potential Cross-Site Request Forgery'),
    ('CWE-200', 'Potential Sensitive Information Exposure'),
    ('CWE-425', 'Potential Forced Browsing (Direct Request)'),
    ('CWE-94', 'Potential Code Injection'),
]


def setup_snapshot(monkeypatch):
    analysis_id = 'D-PRESENTATION-TEST'
    findings = {}
    metadata = {}
    for index, (cwe, _) in enumerate(CWE_LABELS, 1):
        finding = Finding(
            finding_id=f'F-{index:04d}',
            finding_type=FindingType.OTHER,  # simulate old persisted scans
            scan_type=ScanType.DYNAMIC,
            explanation='LLM candidate only, not verified.',
            endpoint='http://localhost:4280/setup.php',
            parameter=None,
            method='GET',
            status=FindingStatus.PROPOSED,
            # deliberately omitted: historical metadata holds CWE
            proposed_cwe=None,
        )
        findings[finding.finding_id] = finding
        metadata[finding.finding_id] = {
            'analysis_id': analysis_id,
            'proposed_cwe': cwe,
            'suggested_severity': 'MEDIUM',
        }
    monkeypatch.setattr(server, 'FINDINGS', findings)
    monkeypatch.setattr(server, 'FINDING_METADATA', metadata)
    monkeypatch.setattr(server, 'ANALYSES', {
        analysis_id: {
            'analysis_id': analysis_id,
            'analysis_type': 'DYNAMIC',
            'scan_type': 'DYNAMIC',
            'provider': 'TEST',
            'application_name': 'DVWA test display',
            'target': 'http://localhost:4280/',
            'analysis_scope': 'local lab',
            'discovery': {},
            'context_build': {},
        },
    })
    monkeypatch.setattr(server, 'ANALYSIS_SESSIONS', {})
    monkeypatch.setattr(server, 'EVIDENCE_BY_FINDING', {})
    monkeypatch.setattr(server, 'REVIEW_BY_FINDING', {})
    return analysis_id


def test_real_analysis_results_page_renders_cwe_families_and_new_template(monkeypatch):
    analysis_id = setup_snapshot(monkeypatch)
    response = server.app.test_client().get(f'/analysis/{analysis_id}/results')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'Suggested Severity' in html
    assert 'Different proposed CWEs may refer to the same endpoint' in html
    for cwe, label in CWE_LABELS:
        assert cwe in html
        assert label in html
    assert '<td>OTHER</td>' not in html
    assert all(f.status == FindingStatus.PROPOSED for f in server.FINDINGS.values())
    assert len({f.endpoint for f in server.FINDINGS.values()}) == 1


def test_real_finding_detail_uses_same_label_as_table(monkeypatch):
    setup_snapshot(monkeypatch)
    response = server.app.test_client().get('/findings/F-0001')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'Potential Unrestricted File Upload' in html
    assert server.FINDINGS['F-0001'].status == FindingStatus.PROPOSED
