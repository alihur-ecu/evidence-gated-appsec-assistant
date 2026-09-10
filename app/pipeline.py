from human_review import review_finding
from llm_proposer import propose_finding

from runtime_evidence_collector import (
    collect_sql_injection_evidence,
    save_evidence
)

from evidence_gate import evaluate_evidence


def run_pipeline():

    print("\nStarting AppSec evidence pipeline...\n")

    # Step 1: Propose finding
    proposal = propose_finding()

    print("PROPOSED FINDING")
    print(f"Finding type: {proposal.get('finding_type')}")
    print(f"Parameter: {proposal.get('parameter')}")
    print(f"Description: {proposal.get('description')}")
    print(f"Status: {proposal.get('status')}")

    # Step 2: Collect runtime evidence
    print("\nCollecting runtime evidence...\n")

    evidence = collect_sql_injection_evidence()

    # Step 3: Save evidence
    json_file, csv_file = save_evidence(evidence)

    # Step 4: Evaluate evidence
    decision = evaluate_evidence(evidence)

    # Step 5: Show final result
    print("\nFINAL PIPELINE RESULT")

    print(f"Proposed finding: {proposal.get('finding_type')}")
    print(f"Parameter: {proposal.get('parameter')}")
    print(f"Runtime evidence: {evidence.get('runtime_evidence')}")
    print(
        f"Database error detected: "
        f"{evidence.get('database_error_detected')}"
    )
    print(f"Evidence gate decision: {decision}")

    print(f"\nJSON saved to: {json_file}")
    print(f"CSV saved to: {csv_file}")


if __name__ == "__main__":
    run_pipeline()