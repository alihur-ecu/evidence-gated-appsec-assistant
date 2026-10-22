# User Guide — Evidence-Gated AppSec Finding Assistant

**Audience:** application-security testers/analysts, developers receiving findings, educators using authorised labs. The final UI screens and labels must be checked against the code in `Evidence_Gated_AppSec.zip` before submitting screenshots.

## Static workflow

1. Launch the application using `SETUP_GUIDE.md`.
2. Choose the static analysis workflow and upload an authorised source ZIP.
3. Select a valid LLM provider (or supported non-LLM mode, if the final application permits).
4. Start the analysis. Review proposed candidates, source paths and their origin (LLM or source-pattern).
5. Open a finding to see the verification status and source evidence. **PENDING** means not yet verified; **NEEDS_HUMAN** means evidence is inconclusive or not sufficient for a proof verdict.
6. Enter human-review decision and severity where appropriate; export results if needed.

## Dynamic workflow

1. Start the authorised local lab target (DVWA was used in the project).
2. Select the dynamic workflow and enter the local URL and any necessary credentials through the application UI.
3. Run bounded discovery and review proposed candidates. No finding should be treated as proven solely because an LLM suggested it.
4. Open a SQLi candidate and trigger verification using the UI, if supported in the final release.
5. Inspect baseline/control/syntax evidence and Oracle result before recording final human-review disposition.
6. Save the scan or export JSON/CSV if those functions are present in the final code.

## Meanings of statuses

- **PENDING / PROPOSED:** candidate has not received a supported verification verdict.
- **PROVED:** defined deterministic evidence condition was met for a supported test; not a guarantee of unrestricted exploitability.
- **REFUTED:** the bounded checks did not find a qualifying signal; this does **not** certify safety.
- **NEEDS_HUMAN:** evidence is ambiguous, incomplete or outside supported verification coverage.

## User safety and privacy

Only test targets you own or have permission to assess. Never include production credentials or API tokens in screenshots or GitHub issues. Cloud LLM mode may transmit authorised source excerpts to the provider; use the local model when external sharing is inappropriate.
