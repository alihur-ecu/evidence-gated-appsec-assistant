# Evidence-Gated AppSec Finding Assistant — final technical handover

CSI6224 Applied Project · Semester 2, 2026  
**Team:** Gabriel Andrés Gil Camelo, Irtifa Sarwath, Md Mahmud Hassan Rabby  
**Supervisors:** Dr M Ali Hur and Taylah Griffiths

**Code baseline:** source uploaded as `Evidence-Gated AppSec Finding Assistant.zip` on 22 October 2026. The archive contains application source, tests and support scripts. This handover combines that source with updated documentation. The ZIP checksum and execution details are recorded in [verification status](docs/HANDOVER_CHANGELOG_AND_VERIFICATION_STATUS.md). **This does not confirm that the same version has been merged into GitHub master.**

## Purpose and scope

**AI proposes → deterministic evidence verifies → human decides.** The system proposes findings from uploaded source or an authorised local lab target. Its verifier evaluates only supported finding types, records evidence and separates the independent decision from human acceptance/severity. This is a research/teaching prototype, not a production scanner.

## Getting started

1. [Setup and Run Guide](docs/SETUP_GUIDE.md) — Python environment, Flask entrypoint, credentials and local lab prerequisites.
2. [Architecture](docs/ARCHITECTURE.md) and [Module Reference](docs/MODULE_REFERENCE.md) — components, call paths and source locations.
3. [Oracle Rule Catalogue](docs/ORACLE_RULE_CATALOGUE.md) — actual current SQLi decision rules and code ownership distinction.
4. [User Guide](docs/USER_GUIDE.md) — static and dynamic workflow, review and exports.
5. [Testing Guide](docs/TESTING_GUIDE.md) and [Results and Evidence](docs/RESULTS_AND_EVIDENCE.md) — how to rerun tests, what was actually tested here, and team-reported outcomes.
6. [LLMs and third-party services](docs/THIRD_PARTY_AND_LLM.md), [Data and Processing](docs/DATA_AND_PROCESSING.md).
7. [Developer Guide](docs/DEVELOPER_GUIDE.md), [Known Issues](docs/KNOWN_ISSUES_AND_FUTURE_WORK.md), [Verification Status](docs/HANDOVER_CHANGELOG_AND_VERIFICATION_STATUS.md) and [Handover Checklist](docs/HANDOVER_CHECKLIST.md).

## Important boundaries

- The static source candidate generator is a **proposer**, not an Oracle. Static SQLi has rule-based verification; static XSS observations always need a human. Runtime proof logic exists for SQLi only.
- **PROVED** means the present project rules found qualifying evidence, not externally validated certainty. **REFUTED** means no qualifying evidence was found within bounded checks, not that the target is safe.
- LLM adapters support local **LM Studio** and hosted **OpenAI**/**Gemini**. Which service produced a particular saved run must be recorded; adapters existing in source do not prove provider connectivity.
- Do not upload `.env`, keys, target passwords or session cookies. An optional `.env.example` has no secrets.
- A controlled, labelled LLM-only vs evidence-gated precision/recall/F1 benchmark was not completed.
- **GitHub master status must be checked separately.** Packaging this ZIP does not push to GitHub or overwrite team work.

## AI tools acknowledgement

For the project's academic acknowledgement, see [AI Tools Acknowledgement](docs/AI_TOOLS_ACKNOWLEDGEMENT.md). This separates assistance used to prepare project materials from the LLM services implemented in the application, and identifies details to confirm before submission.

