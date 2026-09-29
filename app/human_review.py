def review_finding(proposal, evidence, decision):
    """
    Let a human review the evidence-gated finding.
    """

    print("\nHUMAN REVIEW")
    print("-----------------------------")

    print(f"Finding: {proposal.get('finding_type')}")
    print(f"Parameter: {proposal.get('parameter')}")
    print(f"Description: {proposal.get('description')}")

    print("\nEvidence:")
    print(f"Runtime evidence: {evidence.get('runtime_evidence')}")
    print(
        f"Database error detected: "
        f"{evidence.get('database_error_detected')}"
    )

    print(f"\nEvidence gate decision: {decision}")

    print("\nChoose an action:")
    print("1. ACCEPT")
    print("2. REJECT")
    print("3. EDIT")

    choice = input("\nEnter 1, 2, or 3: ").strip()

    if choice == "1":
        return {
            "human_decision": "ACCEPTED",
            "final_description": proposal.get("description")
        }

    elif choice == "2":
        return {
            "human_decision": "REJECTED",
            "final_description": proposal.get("description")
        }

    elif choice == "3":
        edited_description = input(
            "\nEnter the edited description: "
        )

        return {
            "human_decision": "EDITED",
            "final_description": edited_description
        }

    else:
        return {
            "human_decision": "INVALID",
            "final_description": proposal.get("description")
        }


if __name__ == "__main__":
    print(
        "This file is designed to be called "
        "from the main pipeline."
    )