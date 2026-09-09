import json
from pathlib import Path


def evaluate_evidence(evidence):
    """
    Decide whether the finding has enough evidence.
    """

    runtime_evidence = evidence.get("runtime_evidence", False)
    database_error_detected = evidence.get(
        "database_error_detected",
        False
    )

    if runtime_evidence and database_error_detected:
        return "CONFIRMED"

    elif runtime_evidence or database_error_detected:
        return "NEEDS_MORE_EVIDENCE"

    else:
        return "REJECTED"


def load_latest_evidence():
    """
    Load the most recent runtime evidence JSON file.
    """

    runs_folder = Path("artifacts") / "runs"

    json_files = list(
        runs_folder.glob("*_runtime_evidence.json")
    )

    if not json_files:
        raise FileNotFoundError(
            "No runtime evidence JSON file found."
        )

    latest_file = max(
        json_files,
        key=lambda path: path.stat().st_mtime
    )

    with latest_file.open(
        "r",
        encoding="utf-8"
    ) as f:
        evidence = json.load(f)

    return evidence, latest_file


if __name__ == "__main__":

    evidence, evidence_file = load_latest_evidence()

    decision = evaluate_evidence(evidence)

    print("\nEVIDENCE GATE RESULT")
    print(f"Evidence file: {evidence_file}")
    print(f"Finding type: {evidence.get('finding_type')}")
    print(f"Parameter: {evidence.get('parameter')}")
    print(f"Runtime evidence: {evidence.get('runtime_evidence')}")
    print(
        "Database error detected:",
        evidence.get("database_error_detected")
    )
    print(f"Decision: {decision}")