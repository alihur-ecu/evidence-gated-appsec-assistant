"""Controlled mock provider for frontend/integration development.

This provider does NOT scan arbitrary applications and does NOT claim that an
LLM has executed. It only returns deterministic candidate proposals for known,
authorised development fixtures. Unknown files return no findings.
"""

from __future__ import annotations

from pathlib import Path


KNOWN_FIXTURE_NAMES = {
    "mock_vulnerable_shop.zip",
}


MOCK_VULNERABLE_SHOP_FINDINGS = [
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/product",
        "parameter": "id",
        "method": "GET",
        "explanation": "Mock proposal: the product id is used in a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/search",
        "parameter": "q",
        "method": "GET",
        "explanation": "Mock proposal: the search term is used in a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/login",
        "parameter": "username,password",
        "method": "POST",
        "explanation": "Mock proposal: login inputs are used in a deliberately vulnerable authentication query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/orders",
        "parameter": "customer",
        "method": "GET",
        "explanation": "Mock proposal: the customer value is used in a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/user",
        "parameter": "id",
        "method": "GET",
        "explanation": "Mock proposal: the user id is inserted into a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/category",
        "parameter": "name",
        "method": "GET",
        "explanation": "Mock proposal: the category name is concatenated into a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/report",
        "parameter": "status",
        "method": "GET",
        "explanation": "Mock proposal: the report status is inserted into a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/admin/find",
        "parameter": "email",
        "method": "GET",
        "explanation": "Mock proposal: the email value is concatenated into a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/inventory",
        "parameter": "sku",
        "method": "GET",
        "explanation": "Mock proposal: the SKU value is inserted into a deliberately vulnerable SQL query in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
    },
    {
        "finding_type": "SQL_INJECTION",
        "endpoint": "/sort",
        "parameter": "column,direction",
        "method": "GET",
        "explanation": "Mock proposal: user-controlled sort identifiers are inserted into a deliberately vulnerable ORDER BY clause in the controlled training fixture.",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "MEDIUM",
    },
    {
        "finding_type": "XSS",
        "endpoint": "/comment",
        "parameter": "text",
        "method": "GET",
        "explanation": "Mock proposal: comment text is reflected without safe output handling in the controlled training fixture.",
        "proposed_cwe": "CWE-79",
        "suggested_severity": "MEDIUM",
    },
    {
        "finding_type": "XSS",
        "endpoint": "/profile",
        "parameter": "bio",
        "method": "POST",
        "explanation": "Mock proposal: stored profile content is rendered without safe output handling in the controlled training fixture.",
        "proposed_cwe": "CWE-79",
        "suggested_severity": "MEDIUM",
    },
    {
        "finding_type": "XSS",
        "endpoint": "/welcome",
        "parameter": "name",
        "method": "GET",
        "explanation": "Mock proposal: the name value is reflected without safe output handling in the controlled training fixture.",
        "proposed_cwe": "CWE-79",
        "suggested_severity": "MEDIUM",
    },
]


def run_mock_static_analysis(*, source_path: str, original_filename: str, application_name: str) -> dict:
    """Return the stable provider contract for a known fixture."""
    source_name = Path(original_filename).name
    is_known_fixture = source_name.lower() in KNOWN_FIXTURE_NAMES

    findings = MOCK_VULNERABLE_SHOP_FINDINGS if is_known_fixture else []

    return {
        "analysis_mode": "STATIC",
        "application_name": application_name,
        "source_file": source_name,
        "provider": "MOCK",
        "context_source": "SOURCE_CODE",
        "fixture_recognised": is_known_fixture,
        "message": (
            "Known development fixture recognised. Deterministic mock candidate proposals were loaded for workflow testing."
            if is_known_fixture
            else "No mock fixture results are registered for this source. No vulnerabilities were invented."
        ),
        "findings": [dict(item) for item in findings],
    }
