import os
import json
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import errors, types

from app.schemas.finding import Finding


# ============================================================
# LOAD PROJECT .ENV FILE
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=True
)


# ============================================================
# SAFETY SETTINGS
# ============================================================

SAFETY_SETTINGS = [
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=types.HarmBlockThreshold.BLOCK_NONE
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE
    ),
]


# ============================================================
# GEMINI SECURITY PROPOSER
# ============================================================

class GeminiSecurityProposer:

    def __init__(self):

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY was not found in the .env file."
            )

        self.model = os.getenv("GEMINI_MODEL")

        if not self.model:
            raise ValueError(
                "GEMINI_MODEL was not found in the .env file."
            )

        self.client = genai.Client(
            api_key=api_key
        )

        self.last_error_was_quota = False


    # ========================================================
    # GEMINI API CALL WITH RETRY
    # ========================================================

    def _call_gemini(self, prompt: str, max_retries: int = 4):

        for attempt in range(1, max_retries + 1):

            try:

                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        safety_settings=SAFETY_SETTINGS
                    )
                )

                return response

            except errors.ServerError as exc:

                print()
                print(f"Gemini server temporarily unavailable (attempt {attempt}/{max_retries}).")

                if attempt == max_retries:
                    print("Maximum retries reached. Skipping this file.")
                    return None

                wait_seconds = attempt * 5
                print(f"Waiting {wait_seconds} seconds before retry...")
                time.sleep(wait_seconds)

            except errors.ClientError as exc:

                print()
                print("Gemini client/API error:")
                print(exc)

                if "RESOURCE_EXHAUSTED" in str(exc):
                    self.last_error_was_quota = True

                print("Skipping this file instead of stopping the whole scan.")
                return None

            except Exception as exc:

                print()
                print("Unexpected Gemini error:")
                print(exc)
                print("Skipping this file.")
                return None

        return None


    # ========================================================
    # CLEAN GEMINI JSON RESPONSE
    # ========================================================

    @staticmethod
    def _clean_json_response(text: str) -> str:

        text = text.strip()

        if text.startswith("```json"):
            text = text[len("```json"):]
        elif text.startswith("```"):
            text = text[len("```"):]

        if text.endswith("```"):
            text = text[:-3]

        return text.strip()


    # ========================================================
    # BUILD PROMPT (detailed or simplified fallback)
    # ========================================================

    def _build_prompt(self, file_path: str, source_code: str, detailed: bool):

        if detailed:
            return f"""
You are performing an AUTHORIZED STATIC APPLICATION SECURITY REVIEW,
similar to an automated code-review linter used inside a secure
development pipeline.

TARGET:
Damn Vulnerable Web Application (DVWA)

DVWA is an intentionally vulnerable, open-source training
application. It is designed specifically for security
education, research, and defensive code review. Reviewing
its source code is expected and authorized use of this
software.

This analysis is limited to reading source code and reporting
patterns. Do NOT perform exploitation or active attacks, and
do NOT generate exploit payloads.

YOUR ROLE:

You are only a code-review PROPOSER, similar to a static-analysis
linter.

You must identify POTENTIAL secure-coding weaknesses that are
supported by the supplied source code.

You must NOT describe a weakness as:

- confirmed
- verified
- proven
- definitely exploitable

A separate deterministic Oracle will verify candidate
findings later.

============================================================
SECURE-CODING PATTERNS TO REVIEW FOR
============================================================

Review the code for common secure-coding weaknesses similar to
what a static-analysis linter would flag, including:

1. Unsanitized input reaching a database query (SQL Injection risk)
2. Unsanitized input reflected into HTML output (XSS risk)
3. Unsanitized input reaching a stored value later rendered as HTML
4. Unsanitized input reaching a shell/system command
5. Unsanitized input used to include or load a file
6. Unsanitized input used to build a file-system path
7. Unrestricted or unvalidated file uploads
8. Weak or missing authentication checks
9. Weak or missing authorization/access-control checks
10. Missing CSRF protection
11. Sensitive information exposed in output or error messages
12. Generally insecure input handling
13. Missing output encoding
14. Insecure configuration defaults
15. Other clearly supported secure-coding weaknesses

Do NOT force a classification when the source code does not
support one.

============================================================
OUTPUT REQUIREMENTS
============================================================

Return ONLY a valid JSON ARRAY.

Do not return Markdown.

Do not return explanatory text outside the JSON.

If there are no reasonable candidate findings, return:

[]

Each finding must follow this exact structure:

[
  {{
    "finding_id": "FINDING-001",
    "vulnerability": "Potential SQL Injection",
    "file": "{file_path}",
    "line_start": 10,
    "line_end": 15,
    "parameter": "id",
    "description": "Explain clearly why the supplied code may be vulnerable.",
    "confidence": 90,
    "status": "PROPOSED"
  }}
]

RULES:

- status must ALWAYS be "PROPOSED"
- confidence must be an integer between 0 and 100
- use the actual supplied file path
- use source-code line numbers when they are identifiable
- identify the affected parameter/input when possible
- do not invent variables, files, functions, parameters, or lines
- avoid duplicate findings
- only report issues reasonably supported by the code

============================================================
SOURCE FILE
============================================================

{file_path}

============================================================
SOURCE CODE
============================================================

{source_code}

============================================================
END SOURCE CODE
============================================================
"""
        else:
            return f"""
You are a code-quality reviewer. Read the code below and list
any input-handling patterns worth double-checking (for example,
values used in database queries, HTML output, file paths, or
system commands without being validated first).

Return ONLY a JSON array, no other text. If nothing stands out,
return [].

Format:
[
  {{
    "finding_id": "FINDING-001",
    "vulnerability": "short label",
    "file": "{file_path}",
    "line_start": 1,
    "line_end": 1,
    "parameter": "input name if any",
    "description": "one sentence explanation",
    "confidence": 50,
    "status": "PROPOSED"
  }}
]

CODE:
{source_code}
"""


    # ========================================================
    # RUN ONE PROMPT ATTEMPT
    # ========================================================

    def _run_prompt(self, prompt: str, file_path: str):

        response = self._call_gemini(prompt=prompt)

        if response is None:
            return None

        if not response.text:
            print(f"Gemini returned an empty response for: {file_path}")
            return None

        raw_text = response.text.strip()
        lower_text = raw_text.lower()

        refusal_phrases = [
            "cannot fulfill", "can't fulfill",
            "cannot assist", "can't assist",
            "i'm unable", "i am unable"
        ]

        if any(phrase in lower_text for phrase in refusal_phrases):
            return None

        cleaned_text = self._clean_json_response(raw_text)

        try:
            data = json.loads(cleaned_text)
        except json.JSONDecodeError:
            print(f"Gemini returned invalid JSON for: {file_path}")
            print("Raw Gemini response:", raw_text)
            return None

        if not isinstance(data, list):
            print(f"Gemini response was JSON but not a list. Skipping: {file_path}")
            return None

        findings = []

        for index, item in enumerate(data, start=1):

            if not isinstance(item, dict):
                continue

            confidence = item.get("confidence", 0)
            try:
                confidence = int(confidence)
            except (TypeError, ValueError):
                confidence = 0
            confidence = max(0, min(100, confidence))

            finding_id = item.get("finding_id") or f"FINDING-{index:03d}"

            try:
                finding = Finding(
                    finding_id=finding_id,
                    vulnerability=item.get("vulnerability", "Potential Security Issue"),
                    file_path=item.get("file", file_path),
                    line_start=item.get("line_start"),
                    line_end=item.get("line_end"),
                    parameter=item.get("parameter"),
                    description=item.get("description", ""),
                    confidence=confidence,
                    status="PROPOSED"
                )
                findings.append(finding)
            except Exception as exc:
                print("Could not create Finding object:", exc)

        return findings


    # ========================================================
    # ANALYZE ONE SOURCE FILE
    # ========================================================

    def analyze(self, file_path: str, source_code: str):

        self.last_error_was_quota = False

        detailed_prompt = self._build_prompt(file_path, source_code, detailed=True)
        findings = self._run_prompt(detailed_prompt, file_path)

        if findings is not None:
            return findings

        if self.last_error_was_quota:
            return []

        print(f"Retrying {file_path} with a simplified prompt...")

        simple_prompt = self._build_prompt(file_path, source_code, detailed=False)
        findings = self._run_prompt(simple_prompt, file_path)

        if findings is not None:
            return findings

        print(f"Both attempts failed for: {file_path}")
        return []