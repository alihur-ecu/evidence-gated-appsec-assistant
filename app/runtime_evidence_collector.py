"""
Runtime evidence collector for SQL Injection verification.

This module is based on the original DVWA runtime evidence collector
developed by the project team.

The collector does NOT decide whether a vulnerability is accepted.
Its responsibility is only to:

1. Execute deterministic verification requests.
2. Observe application behaviour.
3. Record reproducible evidence.

The Evidence Gate evaluates the collected evidence separately.

Current MVP scope:
- Local DVWA environment only.
- SQL Injection only.
- GET requests only.
"""

from __future__ import annotations

import csv
import json
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

from app.models.finding import Finding, FindingType


# ======================================================================
# LOCAL LAB CONFIGURATION
#
# Environment variables can override these defaults.
# The defaults match the team's local DVWA development environment.
# ======================================================================

BASE_URL = os.getenv(
    "DVWA_BASE_URL",
    "http://localhost:4280",
).rstrip("/")

USERNAME = os.getenv(
    "DVWA_USERNAME",
    "admin",
)

PASSWORD = os.getenv(
    "DVWA_PASSWORD",
    "password",
)

REQUEST_TIMEOUT = 10


# ======================================================================
# DVWA LOGIN
# ======================================================================

def login_to_dvwa(session: requests.Session) -> None:
    """
    Authenticate to the local DVWA instance.

    The authenticated requests.Session is reused by the verifier so
    cookies and the DVWA security setting remain consistent.
    """

    login_url = f"{BASE_URL}/login.php"

    response = session.get(
        login_url,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Could not open DVWA login page. "
            f"HTTP status: {response.status_code}"
        )

    # DVWA normally includes a CSRF token named user_token.
    token_match = re.search(
        r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
        response.text,
    )

    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
    }

    if token_match:
        login_data["user_token"] = token_match.group(1)

    response = session.post(
        login_url,
        data=login_data,
        allow_redirects=True,
        timeout=REQUEST_TIMEOUT,
    )

    if "Logout" not in response.text:
        raise RuntimeError(
            "DVWA login failed. Check the local DVWA credentials."
        )


# ======================================================================
# HELPERS
# ======================================================================

def count_dvwa_records(response_text: str) -> int:
    """
    Count records returned by the DVWA SQL Injection page.

    This signal is specific to the current DVWA MVP and should later
    be replaced/extended by vulnerability-specific verifier adapters.
    """

    return response_text.count("First name:")


def detect_database_error(response_text: str) -> bool:
    """
    Detect explicit database-error messages in the HTTP response.

    This is an auxiliary signal only and is never required for the
    Evidence Gate to prove SQL Injection.

    The indicators intentionally use specific error phrases rather
    than generic words such as 'mysql' or 'mariadb', because those
    generic terms may legitimately appear elsewhere in the page HTML.
    """

    lower_text = response_text.lower()

    indicators = (
        "you have an error in your sql syntax",
        "warning: mysql",
        "warning: mysqli",
        "mysqli_sql_exception",
        "mysql_fetch",
        "mysqli_fetch",
        "sqlstate[",
        "pdoexception",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    )

    return any(
        indicator in lower_text
        for indicator in indicators
    )


def build_request_record(
    response: requests.Response,
    parameter: str,
    payload: str,
) -> dict:
    """
    Convert an executed HTTP request/response into a serialisable
    evidence record suitable for storage and display in the UI.
    """

    prepared = response.request

    request_text = (
        f"{prepared.method} {prepared.url}\n"
        f"User-Agent: "
        f"{prepared.headers.get('User-Agent', 'python-requests')}"
    )

    body_excerpt = response.text[:2500]

    return {
        "method": prepared.method,
        "url": prepared.url,
        "parameter": parameter,
        "payload": payload,
        "request_text": request_text,
        "response": {
            "status_code": response.status_code,
            "response_length": len(response.text),
            "result_count": count_dvwa_records(response.text),
            "database_error_detected": detect_database_error(
                response.text
            ),
            "body_excerpt": body_excerpt,
        },
    }


def execute_test(
    session: requests.Session,
    target_url: str,
    parameter: str,
    payload: str,
) -> dict:
    """
    Execute one deterministic GET request against the configured
    SQL Injection endpoint.
    """

    params = {
        parameter: payload,
        "Submit": "Submit",
    }

    response = session.get(
        target_url,
        params=params,
        timeout=REQUEST_TIMEOUT,
    )

    return build_request_record(
        response=response,
        parameter=parameter,
        payload=payload,
    )


# ======================================================================
# SQL INJECTION VERIFIER
# ======================================================================

def collect_sql_injection_evidence(
    finding: Finding,
) -> dict:
    """
    Collect deterministic runtime evidence for one proposed SQL
    Injection Finding.

    The test performs three requests:

        1. Baseline
        2. SQL TRUE condition
        3. SQL FALSE condition

    The collector records observations only.

    It does NOT decide PROVED / REFUTED / NEEDS_HUMAN.
    """

    if finding.finding_type != FindingType.SQL_INJECTION:
        raise ValueError(
            "SQL Injection verifier received a non-SQL-Injection finding."
        )

    if finding.method.upper() != "GET":
        raise ValueError(
            "The current SQL Injection MVP verifier supports GET only."
        )

    session = requests.Session()

    session.headers.update({
        "User-Agent": "Evidence-Gated-AppSec/0.1"
    })

    login_to_dvwa(session)

    # DVWA vulnerability behaviour depends on security level.
    session.cookies.set(
        "security",
        "low",
    )

    endpoint = finding.endpoint.lstrip("/")

    target_url = urljoin(
        f"{BASE_URL}/",
        endpoint,
    )

    # ------------------------------------------------------------------
    # Three deterministic test conditions
    # ------------------------------------------------------------------

    baseline_payload = "1"

    true_payload = "1' OR '1'='1' #"

    false_payload = "1' AND '1'='2' #"

    baseline = execute_test(
        session,
        target_url,
        finding.parameter,
        baseline_payload,
    )

    true_condition = execute_test(
        session,
        target_url,
        finding.parameter,
        true_payload,
    )

    false_condition = execute_test(
        session,
        target_url,
        finding.parameter,
        false_payload,
    )

    baseline_count = baseline["response"]["result_count"]
    true_count = true_condition["response"]["result_count"]
    false_count = false_condition["response"]["result_count"]

    # ------------------------------------------------------------------
    # Evidence signals
    #
    # These are observations.
    # The Evidence Gate decides what these observations mean.
    # ------------------------------------------------------------------

    behaviour_changed = (
        true_count != baseline_count
        or false_count != baseline_count
    )

    true_false_difference = (
        true_count != false_count
    )

    true_expands_results = (
        true_count > baseline_count
    )

    false_reduces_results = (
        false_count < true_count
    )

    database_error_detected = any([
        baseline["response"]["database_error_detected"],
        true_condition["response"]["database_error_detected"],
        false_condition["response"]["database_error_detected"],
    ])

    all_requests_successful = all([
        baseline["response"]["status_code"] == 200,
        true_condition["response"]["status_code"] == 200,
        false_condition["response"]["status_code"] == 200,
    ])

    timestamp = datetime.now(timezone.utc)

    run_id = timestamp.strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    evidence = {
        "finding_id": finding.finding_id,
        "run_id": run_id,
        "timestamp_utc": timestamp.isoformat(),
        "target": BASE_URL,
        "endpoint": finding.endpoint,
        "finding_type": finding.finding_type.value,
        "parameter": finding.parameter,
        "method": finding.method.upper(),

        "verification_type":
            "SQL_INJECTION_BOOLEAN_BEHAVIOUR_COMPARISON",

        "execution_status": "COMPLETED",

        "tests": {
            "baseline": baseline,
            "true_condition": true_condition,
            "false_condition": false_condition,
        },

        "signals": {
            "all_requests_successful":
                all_requests_successful,

            "baseline_result_count":
                baseline_count,

            "true_result_count":
                true_count,

            "false_result_count":
                false_count,

            "behaviour_changed":
                behaviour_changed,

            "true_false_difference":
                true_false_difference,

            "true_expands_results":
                true_expands_results,

            "false_reduces_results":
                false_reduces_results,

            "database_error_detected":
                database_error_detected,
        },
    }

    return evidence


# ======================================================================
# EVIDENCE STORAGE
# ======================================================================

def save_evidence(
    evidence: dict,
) -> tuple[Path, Path]:
    """
    Store the complete evidence record as JSON and append a compact
    summary row to CSV.

    JSON is the primary evidence artifact.
    CSV is only a convenient evaluation/export format.
    """

    artifacts_dir = (
        Path("artifacts")
        / "runs"
    )

    artifacts_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_id = evidence["run_id"]

    # ------------------------------------------------------------------
    # Full JSON evidence
    # ------------------------------------------------------------------

    json_file = (
        artifacts_dir
        / f"{run_id}_runtime_evidence.json"
    )

    with json_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=2,
        )

    # ------------------------------------------------------------------
    # Compact CSV summary
    # ------------------------------------------------------------------

    csv_file = (
        artifacts_dir
        / "runtime_evidence_results.csv"
    )

    signals = evidence["signals"]

    csv_row = {
        "run_id":
            evidence["run_id"],

        "finding_id":
            evidence["finding_id"],

        "timestamp_utc":
            evidence["timestamp_utc"],

        "target":
            evidence["target"],

        "endpoint":
            evidence["endpoint"],

        "finding_type":
            evidence["finding_type"],

        "parameter":
            evidence["parameter"],

        "baseline_result_count":
            signals["baseline_result_count"],

        "true_result_count":
            signals["true_result_count"],

        "false_result_count":
            signals["false_result_count"],

        "behaviour_changed":
            signals["behaviour_changed"],

        "true_false_difference":
            signals["true_false_difference"],

        "database_error_detected":
            signals["database_error_detected"],
    }

    file_exists = csv_file.exists()

    with csv_file.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=csv_row.keys(),
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(csv_row)

    return json_file, csv_file


# ======================================================================
# MANUAL DEVELOPMENT TEST
# ======================================================================

if __name__ == "__main__":

    example_finding = Finding(
        finding_id="DEV-SQLI-001",
        finding_type=FindingType.SQL_INJECTION,
        endpoint="/vulnerabilities/sqli/",
        parameter="id",
        method="GET",
        explanation=(
            "Development finding used to test the "
            "runtime evidence collector."
        ),
    )

    collected_evidence = (
        collect_sql_injection_evidence(
            example_finding
        )
    )

    json_path, csv_path = save_evidence(
        collected_evidence
    )

    print("\nRUNTIME EVIDENCE COLLECTED")
    print(
        json.dumps(
            collected_evidence,
            indent=2,
        )
    )

    print(
        f"\nJSON evidence saved to: "
        f"{json_path}"
    )

    print(
        f"CSV summary saved to: "
        f"{csv_path}"
    )