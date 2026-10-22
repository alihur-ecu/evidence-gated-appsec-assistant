# Testing and reproducibility guide

## Install prerequisites

From the repository root in a fresh Python virtual environment:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

The source also contains `test_lmstudio_connection.py` in the root; running `python -m pytest -q` may collect it and requires the provider SDK. For the project's full checks after dependency installation, run **both** the `tests/` suite and relevant integration/connection checks on the team's machine.

## Oracle-focused offline test coverage

During this documentation review a verified **148-test selection passed**; see `RESULTS_AND_EVIDENCE.md`. The full suite could not be run here because of missing external dependencies. This is **not** evidence of a reproducible DVWA demo.

## Static controlled demonstration

1. Choose the configured LLM model and check it is loaded/available.
2. From Home, upload a permitted mock-shop source ZIP; note ZIP SHA-256 and language coverage.
3. Record candidate count and `proposal_origins`: `LLM` vs `STATIC_SOURCE_PATTERN`.
4. Open a supported SQLi finding and click Verify; inspect its source lines and evidence/decision.
5. If testing XSS, check the source observations and that verdict remains NEEDS_HUMAN.
6. Save scan, set a human review decision, and export redacted evidence/CSV/JSON.

## Dynamic controlled demonstration

1. Start local DVWA and confirm the URL and DVWA security mode. Never test third-party hosts without authorisation.
2. Configure `LLM_PROVIDER` and supported login mode. Start a dynamic scan and record observed endpoints/forms.
3. For a SQLi proposal with a supported parameter, open Verify and inspect the baseline, neutral controls, syntax probes, status/length/digest/error family and Oracle decision.
4. Confirm model-suggested severity and human-final severity remain independent.
5. Save the scan/report and record run ID, configured model ID, environment and observed result.

## Report accuracy and limitations

- The project's SQLi rule is a heuristic, not a benchmark-derived detector.
- If model output is inconsistent across runs, preserve timestamps, provider/model parameters and input source hash.
- Pending means not verified; it is not proof of safety.
- Do not claim precision/recall/F1; the planned labelled dataset/benchmark was not completed.
