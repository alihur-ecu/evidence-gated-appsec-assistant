import json
import time
from datetime import datetime
from pathlib import Path

from app.static_analysis.collector import add_line_numbers
from app.llm.proposer import GeminiSecurityProposer


# ============================================================
# TARGET FILES
# ============================================================
# Scoped to the actual SQLi vulnerable files only, matching
# the MVP priority in the proposal. Widen this list later
# once the SQLi workflow is fully working.

TARGET_FILES = [
    r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities\sqli\source\low.php",
    r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities\sqli\source\medium.php",
    r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities\sqli\source\high.php",
]

FINDINGS_DIR = Path("data/findings")


def load_target_files():
    """
    Reads each target file directly and adds line numbers,
    without scanning the whole folder.
    """

    collected_files = []

    for file_path in TARGET_FILES:

        path = Path(file_path)

        if not path.exists():
            print(f"WARNING: file not found, skipping: {file_path}")
            continue

        try:
            source_code = path.read_text(encoding="utf-8", errors="ignore")

            collected_files.append({
                "file_path": str(path),
                "source_code": add_line_numbers(source_code)
            })

        except Exception as e:
            print(f"Could not read {file_path}: {e}")

    return collected_files


def save_findings_to_json(findings):
    """
    Saves all findings from this run into one timestamped
    JSON file under data/findings/.
    """

    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = FINDINGS_DIR / f"findings_{timestamp}.json"

    findings_as_dicts = [finding.model_dump() for finding in findings]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings_as_dicts, f, indent=2)

    print(f"\nSaved {len(findings)} findings to: {output_path}")


# ============================================================
# MAIN
# ============================================================

print("=" * 50)
print("DVWA GEMINI STATIC SECURITY SCANNER (SQLi files only)")
print("=" * 50)

files = load_target_files()

print(f"\nTotal target files loaded: {len(files)}")

analyzer = GeminiSecurityProposer()

all_findings = []
quota_exhausted = False

for index, file in enumerate(files):

    if quota_exhausted:
        print("\nSkipping remaining files - daily quota already exhausted.")
        break

    print("\nAnalyzing:")
    print(file["file_path"])

    findings = analyzer.analyze(
        file["file_path"],
        file["source_code"]
    )

    if analyzer.last_error_was_quota:
        print("\nDaily Gemini quota exhausted. Stopping the scan early.")
        quota_exhausted = True
        continue

    all_findings.extend(findings)

    if index != len(files) - 1:
        time.sleep(5)


print("\n================================")
print("ANALYSIS COMPLETED")
print("================================")

print(f"Total findings: {len(all_findings)}")

for finding in all_findings:
    print("\n----------------")
    print(finding)

if all_findings:
    save_findings_to_json(all_findings)
else:
    print("\nNo findings to save.")