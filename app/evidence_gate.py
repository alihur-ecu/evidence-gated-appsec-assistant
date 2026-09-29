import json
from pathlib import Path


def evaluate_evidence(evidence):
    """
    Evaluate deterministic runtime evidence.

    The LLM does not make this decision.

    Possible results:
    - PROVED
    - REFUTED
    - NEEDS_HUMAN
    """

    signals = evidence.get("signals", {})

    all_requests_successful = signals.get(
        "all_requests_successful",
        False
    )

    behaviour_changed = signals.get(
        "behaviour_changed",
        False
    )

    true_false_difference = signals.get(
        "true_false_difference",
        False
    )

    true_expands_results = signals.get(
        "true_expands_results",
        False
    )

    false_reduces_results = signals.get(
        "false_reduces_results",
        False
    )

    # ---------------------------------------
    # 1. Incomplete evidence
    # ---------------------------------------

    if not all_requests_successful:
        return "NEEDS_HUMAN"

    # ---------------------------------------
    # 2. Strong evidence supporting SQLi
    # ---------------------------------------

    if (
        behaviour_changed
        and true_false_difference
        and true_expands_results
        and false_reduces_results
    ):
        return "PROVED"

    # ---------------------------------------
    # 3. No meaningful behavioural difference
    # ---------------------------------------

    if (
        not behaviour_changed
        and not true_false_difference
    ):
        return "REFUTED"

    # ---------------------------------------
    # 4. Mixed or ambiguous evidence
    # ---------------------------------------

    return "NEEDS_HUMAN"


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
    ) as file:
        evidence = json.load(file)

    return evidence, latest_file


if __name__ == "__main__":

    evidence, evidence_file = load_latest_evidence()

    decision = evaluate_evidence(evidence)

    signals = evidence.get("signals", {})

    print("\nEVIDENCE GATE RESULT")
    print("--------------------------------")

    print(
        f"Evidence file: "
        f"{evidence_file}"
    )

    print(
        f"Finding ID: "
        f"{evidence.get('finding_id')}"
    )

    print(
        f"Finding type: "
        f"{evidence.get('finding_type')}"
    )

    print(
        f"Parameter: "
        f"{evidence.get('parameter')}"
    )

    print(
        f"Baseline result: "
        f"{signals.get('baseline_result_count')}"
    )

    print(
        f"TRUE result: "
        f"{signals.get('true_result_count')}"
    )

    print(
        f"FALSE result: "
        f"{signals.get('false_result_count')}"
    )

    print(
        f"Behaviour changed: "
        f"{signals.get('behaviour_changed')}"
    )

    print(
        f"TRUE/FALSE difference: "
        f"{signals.get('true_false_difference')}"
    )

    print(
        f"TRUE expands results: "
        f"{signals.get('true_expands_results')}"
    )

    print(
        f"FALSE reduces results: "
        f"{signals.get('false_reduces_results')}"
    )

    print(
        f"\nDecision: {decision}"
    )