# Handover changes and independent verification status

**Reviewed on:** 22 October 2026  
**Uploaded baseline ZIP:** `Evidence-Gated AppSec Finding Assistant.zip`  
**Uploaded baseline SHA-256:** `5b6ae00b278fa089cc9a45591286cdaca1e5c727561dddef8e22135741a8688a`

The user previously referred to the working ZIP as `Evidence_Gated_AppSec.zip`, but the actual uploaded source filename is shown above. **This uploaded archive—not the old `gabriel-current_2.zip` snapshot—was used for the technical review.** The existence of a local ZIP does not confirm GitHub `master` matches it.

## Completed in this package

- Combined the actual uploaded application source and tests with current technical handover docs.
- Added `beautifulsoup4>=4.12,<5` to `requirements.txt`, because `app/dynamic_analysis/discovery.py` imports `bs4`. Added `requirements-dev.txt` for `pytest`. No application behavioural code was edited.
- Added root `.env.example` with **no live secrets**; added setup/documentation links in `README.md`.
- Regenerated `MODULE_REFERENCE.md` from actual Python AST with current paths and definition line numbers.
- Rewrote architecture, Oracle rule catalogue, setup, third-party model configuration, testing status, issues and review notes to match the uploaded code.
- Kept historical team-reported demonstration counts separate from tests actually executed in this review.

## Tests actually executed

- `python -m pytest -q` on a selected 18-module offline subset: **148 passed** (0 failed). Tests cover Oracle, pipeline, source observations, routing, authentication/discovery and models.
- Full `python -m pytest -q --disable-warnings --maxfail=2`: **not completed**. Failed during test collection, because this environment lacks the `openai` package; Flask and `google-genai` were also not installed. Installing dependencies failed due to unavailable network access.
- **No live DVWA scan**, **no mock-shop end-to-end run**, **no UI runtime smoke test** here. No accuracy benchmark computed.

## Checks the team still must complete

| Item | Status |
|---|---|
| GitHub `master` contains this reviewed code and handover docs | **Not checked / not pushed here** |
| All teammate changes represented in final `master` | **Needs team review** |
| Complete dependency-backed test suite on development machine | **Not confirmed** |
| LM Studio / OpenAI / Gemini provider connection with actual models | **Not confirmed** |
| Reproduced DVWA/mock-shop demonstration and redacted evidence | **Not confirmed** |
| Exact GitHub commit SHA / release tag for supervisor | **Not supplied** |
| AI-use acknowledgement checked by team | **Needs human confirmation** |
