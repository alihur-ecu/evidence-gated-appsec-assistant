import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


def login_dvwa(base_url: str, username: str = "admin", password: str = "password") -> requests.Session:
    """
    Authenticate against DVWA and return a requests.Session with the
    resulting session cookie attached.

    DVWA requires a CSRF token (user_token) that is embedded in the
    login page HTML, so we fetch the login page first to extract it
    before submitting credentials.
    """
    session = requests.Session()

    login_page = session.get(f"{base_url}/login.php", timeout=10)

    token_match = re.search(
        r"user_token['\"]\s+value='([a-f0-9]+)'", login_page.text
    )
    if not token_match:
        raise RuntimeError(
            "Could not find CSRF user_token on DVWA login page. "
            "Is DVWA running and reachable at " + base_url + "?"
        )

    user_token = token_match.group(1)

    session.post(
        f"{base_url}/login.php",
        data={
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": user_token,
        },
        timeout=10,
    )

    return session


def run_probe(url: str, method: str = "GET", session: requests.Session | None = None) -> dict:
    """
    Perform a single HTTP request against the target and capture
    reproducible evidence about the response.

    If a `session` is provided (e.g. an authenticated DVWA session),
    it is used so that cookies persist across requests. Otherwise a
    plain unauthenticated GET is made.
    """
    http_client = session if session is not None else requests

    response = http_client.get(url, timeout=10)

    timestamp = datetime.now(timezone.utc)
    run_id = timestamp.strftime("%Y%m%d_%H%M%S_%f")

    evidence = {
        "run_id": run_id,
        "timestamp_utc": timestamp.isoformat(),
        "target": url,
        "method": method,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type"),
        "response_length": len(response.content),
        "response_body": response.text,
    }

    return evidence


def save_evidence(evidence: dict) -> Path:
    """Persist a probe evidence dict to artifacts/runs/<run_id>_http_probe.json"""
    artifacts_dir = Path("artifacts") / "runs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    evidence_file = artifacts_dir / f"{evidence['run_id']}_http_probe.json"

    with evidence_file.open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, ensure_ascii=False)

    return evidence_file


def main():
    if len(sys.argv) != 2:
        print('Usage: python app/http_probe.py "<URL>"')
        sys.exit(1)

    target = sys.argv[1]
    print(f"Target: {target}")

    try:
        evidence = run_probe(target)
        evidence_file = save_evidence(evidence)

        print(f"Status code: {evidence['status_code']}")
        print(f"Content-Type: {evidence['content_type']}")
        print(f"Response length: {evidence['response_length']}")
        print(f"Evidence saved to: {evidence_file}")

    except requests.RequestException as exc:
        print(f"HTTP request failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()