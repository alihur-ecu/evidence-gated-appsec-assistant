# Datasets, inputs, processing and provenance

## Inputs and boundaries

The source archive contains source-processing logic and automated tests, **not** a packaged DVWA image or the team's mock-shop source ZIP. The team's final summary reports local DVWA and mock-shop runs; these were not reproduced during this handover revision.

- **Static:** a project ZIP file is read by `app/static_analysis/archive.py` (bounded extraction), `collector.py` (file selection) and `context_builder.py` (line-referenced chunks). An LLM and a separate Python-only source-pattern generator may produce candidates.
- **Dynamic:** a permitted local HTTP lab is analysed with `app/dynamic_analysis/discovery.py` (same-origin page/form/parameter discovery), then bounded context is sent to the configured LLM proposer. Oracle verification is a subsequent independent step on supported candidates.
- **Verification evidence:** each supported run records source observations or lab HTTP response metadata/error families with an audit trail. Evidence is distinct from review decisions.
- **Persistence:** scans/reports can be saved and viewed via Scan History and exported in supported formats; confirm the configured local artefact path and test behavior on the team's final machine.

## Results provenance and reproducibility

Record source ZIP name and SHA-256, local DVWA version/security level, provider and actual model ID, prompt/parameters/token budgets, scan ID, chosen finding ID, independent verifier evidence, reviewer decision, Git commit SHA and run timestamp. Do not confuse `STATIC_SOURCE_PATTERN` proposals with LLM-generated proposals.

The planned balanced labelled vulnerability benchmark (precision, recall and F1 versus an LLM-only baseline) was **not completed**. Observed candidate counts are in [Results and Evidence](RESULTS_AND_EVIDENCE.md) and must not be described as a measured detector accuracy score.

## Security

Only analyse authorised/local lab code, and do not upload client data or credentials to online providers. Redact HTTP cookies, secrets and personal data from scan exports or screenshots.
