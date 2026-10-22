# Setup and Run Guide (checked against uploaded source)

Source examined: the team's `Evidence-Gated AppSec Finding Assistant.zip`, 22 October 2026. The actual entrypoint is `app/web/server.py` (`python -m app.web.server`). The application is Flask/Jinja2 with Python source files under `app/`; **no npm frontend build is required by this ZIP**.

## Requirements

- Python 3.13 was used for the local offline test subset during documentation review; do not assume other Python versions have been tested.
- Network access to install `requirements.txt` packages. This archive's `requirements.txt` was corrected to include `beautifulsoup4`, imported by `app/dynamic_analysis/discovery.py`.
- Optional: local DVWA at an authorised local address (historically `http://localhost:4280/`) for dynamic testing; use only in your controlled lab.
- Optional: LM Studio local server and a compatible loaded model, or valid OpenAI/Gemini API credentials for the online providers.

## Windows PowerShell

```powershell
cd "C:\path\to\Evidence-Gated AppSec Finding Assistant"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env to select provider and model; do not push it
python -m app.web.server
```

## macOS/Linux

```bash
cd "/path/to/Evidence-Gated AppSec Finding Assistant"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Edit .env locally to select provider and model
python -m app.web.server
```

Flask normally displays `http://127.0.0.1:5000/`. The `__main__` block currently uses `debug=True`; this is **for local development only**. Do not expose the server on a public interface.

## Local configuration

`app/web/server.py` reads a root-level `.env` directly; no `python-dotenv` dependency is required. `LLM_PROVIDER` is read in `app/analysis/proposers/factory.py`. The supported implemented values are `none`, `gemini`, `openai`, `lmstudio`; `azure_openai` and `custom` are reserved and explicitly not implemented. The code default is `none`. For real static scanning, set `ANALYSIS_PROVIDER=static_source`; the code's web workflow otherwise has a `mock` path.

Local LM Studio source defaults are `LMSTUDIO_BASE_URL=http://localhost:1234/v1`, `LMSTUDIO_MODEL=google/gemma-4-e4b`, `LMSTUDIO_MAX_TOKENS=1024`, `LMSTUDIO_STATIC_MAX_TOKENS=4096` and `LMSTUDIO_TEMPERATURE=0`. These defaults are **source constants**, not evidence that this model is installed or running on your computer.

For online providers, set `OPENAI_API_KEY` and optionally `OPENAI_MODEL`, or `GEMINI_API_KEY` and optionally `GEMINI_MODEL`. Use only authorised material when sharing source/context with cloud providers.

## Verify the handover

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

Check the actual output on your machine. The documentation review passed a **148-test offline subset**, but did not execute the full dependency-backed suite or an end-to-end DVWA scan. See [Results and Evidence](RESULTS_AND_EVIDENCE.md).

## Basic run-through

1. Load the home page. Choose static source ZIP upload or dynamic authorised-local-lab scan.
2. Use a provider that is actually configured and working; `none` creates no model findings.
3. Verify a **supported** candidate on its detail page and inspect the retained evidence.
4. Record a separate human review decision/severity; save analysis and check Scan History/report export.
5. Record the GitHub commit SHA, model ID, environment, test run date and redacted evidence for reproducibility.

## Troubleshooting

- `No module named flask`/`openai`/`google.genai`/`bs4`: install the full `requirements.txt` in your active environment.
- LM Studio connection failure: load a model and enable its local OpenAI-compatible server at the configured port.
- Gemini/OpenAI failure: confirm API access, key and enabled model; never reveal keys in screenshots.
- DVWA authentication/connection: confirm Docker lab availability, local URL and authentication mode; do not switch to an unapproved internet target.
- Re-running the complete test suite may collect `test_lmstudio_connection.py`, which imports the OpenAI SDK. This is expected if dependencies are absent.
