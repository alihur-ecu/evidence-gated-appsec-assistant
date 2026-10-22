# Third-party dependencies and LLM adapters

Source verified in the uploaded application archive on 22 October 2026. **Backend integration in code does not prove a particular service is currently reachable or a model is loaded.**

| Option | Actual source | Configuration | Notes |
|---|---|---|---|
| Local LM Studio | `app/analysis/proposers/lmstudio.py` | `LLM_PROVIDER=lmstudio`, `LMSTUDIO_BASE_URL`, `LMSTUDIO_MODEL`, token limits | Uses OpenAI-compatible client pointed at local server; source default model `google/gemma-4-e4b`, not verified as loaded. |
| OpenAI API | `app/analysis/proposers/openai.py` | `LLM_PROVIDER=openai`, `OPENAI_API_KEY`, `OPENAI_MODEL` | Cloud processing may transmit prompt/source context to provider. |
| Gemini API | `app/analysis/proposers/gemini.py` | `LLM_PROVIDER=gemini`, `GEMINI_API_KEY`, `GEMINI_MODEL` | Cloud processing may transmit prompt/source context to provider. Source default model is `gemini-3.6-flash`; availability not verified. |
| None | `app/analysis/proposers/factory.py` | `LLM_PROVIDER=none` | Factory default: no model-generated findings. |

Factory also recognises `azure_openai` and `custom` but explicitly raises `NotImplementedError` for them; **do not represent these as integrated providers**.

## Code package requirements

`requirements.txt`: `requests`, `Flask`, `google-genai`, `openai`, and (corrected in this handover) `beautifulsoup4` which is imported by dynamic discovery. `requirements-dev.txt` adds `pytest`. Record exact resolved versions from your installation (`python -m pip freeze`); minimum/maximum dependency constraints are **not** a lockfile.

## Provider metadata to record per reproduced scan

Provider selection, actual model ID/version, date, temperature/output limits, language/source used, scan run ID, and whether the target/source was authorised. These values are not recoverable from the mere existence of adapters.

## Privacy, reproducibility and academic AI acknowledgement

Do not send private credentials or unauthorised source code to online services. The system's LLM output is only a hypothesis; Oracle evidence and human judgment are independent.

The project documentation includes an [AI Tools Acknowledgement](AI_TOOLS_ACKNOWLEDGEMENT.md) covering use of both ChatGPT (OpenAI, GPT-6) and Claude (Anthropic; exact model/version to be confirmed), as well as the separate LM Studio/OpenAI/Gemini integrations. Do not guess the model/version used for a particular run. Review and complete the declaration based on actual use; do not claim that an unverified model or documentation assistant was used by every member.
