"""Read-only fixture diagnostic, no LLM calls or runtime probes.

Usage:
    python tools/validate_static_mock.py C:\\path\\to\\mock_vulnerable_shop2026.zip

Reports conservative source-pattern proposals, not verified vulnerabilities.
"""
import sys
from collections import Counter
from pathlib import Path

# Running a script by path places tools/ rather than the repository root
# at sys.path[0]. Resolve imports without requiring a pip installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.analysis.providers.static_source_provider import run_static_source_analysis


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        raise SystemExit("Usage: python tools/validate_static_mock.py PATH_TO_AUTHORiSED_ZIP")
    path = Path(sys.argv[1])
    result = run_static_source_analysis(
        source_path=str(path), original_filename=path.name,
        application_name=path.stem,
    )
    print("=== STATIC SOURCE CANDIDATE DIAGNOSTIC ===")
    coverage = result["context_coverage"]
    print(f"Prepared source files: {coverage['files_selected']}")
    print(f"Bounded context chunks: {coverage['chunks_created']}")
    print(f"Context truncated: {coverage['truncated']}")
    proposals = result["source_pattern_proposals"]
    print(f"Source-pattern proposals: {len(proposals)}")
    print("By category:", dict(Counter(p["finding_type"] for p in proposals)))
    for n, proposal in enumerate(proposals, 1):
        print(f"{n:02d}. {proposal['finding_type']:<15} "
              f"{proposal['endpoint'] or '-':<20} "
              f"{proposal['parameter'] or '-':<15} "
              f"{proposal['source_file']}:{proposal['line_number']}")
    print("All candidates are PROPOSALS, not verified findings.")
    print("=== END ===")

if __name__ == "__main__":
    main()
