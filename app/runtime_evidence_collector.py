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



def login_to_dvwa(session: requests.Session) -> None:

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



def count_dvwa_records(response_text: str) -> int:

    return response_text.count("First name:")


def detect_database_error(response_text: str) -> bool:

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



def collect_sql_injection_evidence(
    finding: Finding,
) -> dict:


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




def save_evidence(
    evidence: dict,
) -> tuple[Path, Path]:


    artifacts_dir = (
        Path("artifacts")
        / "runs"
    )

    artifacts_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_id = evidence["run_id"]



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