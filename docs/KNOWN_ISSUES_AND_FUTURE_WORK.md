# Known issues, limits and future work

**Source-reviewed 22 October 2026; not a completed security assessment.**

1. **SQLi-only runtime verifier:** XSS, CSRF, code injection, file inclusion, upload and other findings may be proposed but cannot be deterministically confirmed through a runtime verifier in this build.
2. **Two-error heuristic includes controls:** `InjectionDifferentialVerifier` counts all non-baseline observations with error signals; it does not limit `test_errors` to the intended syntax probes. The team-reported DVWA controls were clean, but future versions should separate controls and syntax probes in the rule.
3. **Blind SQLi:** the checker primarily reasons from database/parser error signals and response differences, not a comprehensive time/boolean/out-of-band suite.
4. **Static SQLi pattern limitations:** a source-window match is not end-to-end taint analysis and may produce false positives/negatives.
5. **Static XSS is observational:** it never proves exploitability and always returns NEEDS_HUMAN.
6. **LLM variability:** proposals depend on provider, loaded model, token limit, prompt, input coverage and environment. Adapters being present does not establish live connectivity.
7. **Missing benchmark:** no complete labelled LLM-only vs evidence-gated precision/recall/F1 experiment.
8. **Prototype web server:** `app/web/server.py` runs with Flask `debug=True` and uses global in-memory state; do not expose beyond the authorised local lab or treat this as multi-user production deployment.
9. **Fresh-machine verification incomplete:** this documentation review could run 148 offline tests but not the dependency-backed suite or UI/DVWA end-to-end demo.
10. **Data and reports:** confirm that saved Scan History and JSON/CSV exports work after restart; do not store any private tokens or session information in shared evidence.

**Next engineering steps:** run the full suite on the team's environment; preserve reproducible DVWA/mock-shop test cases; tighten control/probe classification; expand runtime verifiers; validate static heuristics with labelled cases; address deployment/authentication and privacy safeguards before any use outside controlled local labs.
