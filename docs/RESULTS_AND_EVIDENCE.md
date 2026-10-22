# Testing results and evidence register

## A. Tests actually run in this documentation review

**Environment:** Python 3.13.5, local offline test runner.

**Command:** selected 18 test modules from the provided archive, covering differential SQLi verification, observation policy, response signals, XSS source observation, discovery/authentication, static pipeline, routing, findings, and aggregators.

**Result:** **148 passed** (all tests in the selected subset); this demonstrates the tested components meet those test cases, **not** vulnerability-detection accuracy. A previous six-module focused run also passed 44 tests (these are a subset, not additional tests).

**Full suite status:** `python -m pytest -q --disable-warnings --maxfail=2` failed during collection because the environment lacks the `openai` package (required by `test_lmstudio_connection.py` and another test). No network package installation was possible. Other uninstalled dependencies include Flask and `google-genai`. **Do not claim the complete suite passed.** Run it in the team's configured development environment after `pip install -r requirements-dev.txt`.

## B. Team-reported demonstration results (not independently reproduced here)

| Scenario | Team-reported observation |
|---|---|
| Local DVWA dynamic scan | 7 candidate findings: 1 SQLi PROVED and 6 PENDING (unverified classes). Reported clean baseline and two controls, with SQL syntax probes producing two recognised error responses; the human reviewer set final severity CRITICAL. |
| Mock-shop static scan | 17 candidate findings (12 LLM and 5 Python source-pattern); 0 PROVED, 1 NEEDS_HUMAN, 16 PENDING in the recorded run. |
| Labelled benchmark | Not completed; no measured precision, recall or F1 improvement versus LLM-only output. |

These numbers were transcribed from the team's uploaded project-summary document; **the source ZIP does not contain the DVWA/mock-shop datasets or exported scans needed to reproduce them**. Do not present the numbers as freshly verified against this code.

## C. Add before supervisor handover

| Evidence | Status | Owner action |
|---|---|---|
| `git rev-parse HEAD` SHA on team GitHub `master` | Missing | Record after merge |
| Full dependency-backed `pytest` output | Not performed here | Run and attach result in permitted repo/docs |
| Final DVWA run ID, local lab configuration and redacted evidence JSON/screenshots | Not supplied | Export and link evidence |
| Final mock-shop source hash, run ID and provider/model | Not supplied | Record reproducible input/evidence |
| User-review record, report CSV/JSON from final app | Not supplied | Link representative redacted exports |

Keep a redacted evidence trail: scan/finding ID → hypothesis → input/control/probe → extracted signals → independent Oracle verdict → human review. Do not commit session cookies, tokens or passwords.
