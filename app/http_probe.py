import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


def main():
    if len(sys.argv) != 2:
        print('Usage: python app/http_probe.py "<URL>"')
        sys.exit(1)

    target = sys.argv[1]

    print(f"Target: {target}")

    try:
        response = requests.get(target, timeout=10)

        timestamp = datetime.now(timezone.utc)
        run_id = timestamp.strftime("%Y%m%d_%H%M%S_%f")

        evidence = {
            "run_id": run_id,
            "timestamp_utc": timestamp.isoformat(),
            "target": target,
            "method": "GET",
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "response_length": len(response.content),
            "response_body": response.text,
        }

        artifacts_dir = Path("artifacts") / "runs"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        evidence_file = artifacts_dir / f"{run_id}_http_probe.json"

        with evidence_file.open("w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2, ensure_ascii=False)

        print(f"Status code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
        print(f"Response length: {len(response.content)}")
        print(f"Evidence saved to: {evidence_file}")

    except requests.RequestException as exc:
        print(f"HTTP request failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()