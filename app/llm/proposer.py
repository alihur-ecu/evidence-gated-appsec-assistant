import os
import json
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import errors

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
# GEMINI SECURITY PROPOSER
# ============================================================

class GeminiSecurityProposer:
    """
    Uses Google Gemini to perform authorized static source-code
    analysis and PROPOSE potential security vulnerabilities.

    Important:
    Gemini only proposes candidate findings.
    It does NOT verify or confirm vulnerabilities.
    Verification will be performed later by the Oracle.
    """

    def __init__(self):

        # ----------------------------------------------------
        # Read API key from .env
        # ----------------------------------------------------

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY was not found in the .env file."
            )

        # ----------------------------------------------------
        # Read model name from .env
        # ----------------------------------------------------

        self.model = os.getenv("GEMINI_MODEL")

        if not self.model:
            raise ValueError(
                "GEMINI_MODEL was not found in the .env file."
            )

        # ----------------------------------------------------
        # Initialize Gemini client
        # ----------------------------------------------------

        self.client = genai.Client(
            api_key=api_key
        )


    # ========================================================
    # GEMINI API CALL WITH RETRY
    # ========================================================

    def _call_gemini(
        self,
        prompt: str,
        max_retries: int = 4
    ):
        """
        Send prompt to Gemini.

        Automatically retries temporary Gemini server errors
        such as 503 high-demand errors.
        """

        for attempt in range(1, max_retries + 1):

            try:

                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt
                )

                return response

            except errors.ServerError as exc:

                print()
                print(
                    f"Gemini server temporarily unavailable "
                    f"(attempt {attempt}/{max_retries})."
                )

                if attempt == max_retries:
                    print(
                        "Maximum retries reached. "
                        "Skipping this file."
                    )
                    return None

                wait_seconds = attempt * 5

                print(
                    f"Waiting {wait_seconds} seconds "
                    f"before retry..."
                )

                time.sleep(wait_seconds)

            except errors.ClientError as exc:

                print()
                print("Gemini client/API error:")
                print(exc)

                print(
                    "Skipping this file instead of "
                    "stopping the whole scan."
                )

                return None

            except Exception as exc:

                print()
                print(
                    "Unexpected Gemini error:"
                )

                print(exc)

                print(
                    "Skipping this file."
                )

                return None

        return None


    # ========================================================
    # CLEAN GEMINI JSON RESPONSE
    # ========================================================

    @staticmethod
    def _clean_json_response(text: str) -> str:
        """
        Remove Markdown code fences if Gemini adds them.
        """

        text = text.strip()

        if text.startswith("```json"):
            text = text[len("```json"):]

        elif text.startswith("```"):
            text = text[len("```"):]

        if text.endswith("```"):
            text = text[:-3]

        return text.strip()


    # ========================================================
    # ANALYZE ONE SOURCE FILE
    # ========================================================

    def analyze(
        self,
        file_path: str,
        source_code: str
    ):
        """
        Analyze one source-code file and return a list
        of Finding objects.
        """

        prompt = f"""
You are performing an AUTHORIZED STATIC APPLICATION SECURITY REVIEW.

TARGET:
Damn Vulnerable Web Application (DVWA)

DVWA is an intentionally vulnerable application used for
security education, research, and defensive testing.

This analysis is limited to source-code review.
Do NOT perform exploitation or active attacks.

YOUR ROLE:

You are only a VULNERABILITY PROPOSER.

You must identify POTENTIAL security weaknesses that are
supported by the supplied source code.

You must NOT describe a vulnerability as:

- confirmed
- verified
- proven
- definitely exploitable

A separate deterministic Oracle will verify candidate
findings later.

============================================================
SECURITY ISSUES TO CONSIDER
============================================================

Look for potential issues including:

1. SQL Injection
2. Reflected Cross-Site Scripting (XSS)
3. Stored Cross-Site Scripting
4. Command Injection
5. File Inclusion
6. Path Traversal
7. Unsafe File Upload
8. Authentication weaknesses
9. Authorization / Access Control weaknesses
10. CSRF
11. Information Disclosure
12. Insecure Input Handling
13. Unsafe Output Encoding
14. Security Misconfiguration
15. Other clearly supported application-security weaknesses

Do NOT force a vulnerability classification when the source
code does not support one.

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


        # ----------------------------------------------------
        # Send to Gemini
        # ----------------------------------------------------

        response = self._call_gemini(
            prompt=prompt
        )

        if response is None:
            return []


        # ----------------------------------------------------
        # Check response text
        # ----------------------------------------------------

        if not response.text:
            print(
                f"Gemini returned an empty response "
                f"for: {file_path}"
            )
            return []


        raw_text = response.text.strip()


        # ----------------------------------------------------
        # Handle model refusal gracefully
        # ----------------------------------------------------

        lower_text = raw_text.lower()

        refusal_phrases = [
            "cannot fulfill",
            "can't fulfill",
            "cannot assist",
            "can't assist",
            "i'm unable",
            "i am unable"
        ]

        if any(
            phrase in lower_text
            for phrase in refusal_phrases
        ):
            print()
            print(
                "Gemini did not analyze this file:"
            )
            print(file_path)

            print(
                "The scan will continue with the next file."
            )

            return []


        # ----------------------------------------------------
        # Clean JSON response
        # ----------------------------------------------------

        cleaned_text = self._clean_json_response(
            raw_text
        )


        # ----------------------------------------------------
        # Parse JSON
        # ----------------------------------------------------

        try:

            data = json.loads(
                cleaned_text
            )

        except json.JSONDecodeError:

            print()
            print(
                "Gemini returned invalid JSON for:"
            )

            print(file_path)

            print()
            print("Raw Gemini response:")
            print(raw_text)

            print()
            print(
                "Skipping this file and continuing."
            )

            return []


        # ----------------------------------------------------
        # Ensure response is a list
        # ----------------------------------------------------

        if not isinstance(data, list):

            print()
            print(
                "Gemini response was JSON, "
                "but it was not a list."
            )

            print(
                f"Skipping file: {file_path}"
            )

            return []


        findings = []


        # ----------------------------------------------------
        # Convert JSON objects into Finding models
        # ----------------------------------------------------

        for index, item in enumerate(
            data,
            start=1
        ):

            if not isinstance(item, dict):
                continue


            # -----------------------------------------------
            # Confidence validation
            # -----------------------------------------------

            confidence = item.get(
                "confidence",
                0
            )

            try:
                confidence = int(confidence)

            except (TypeError, ValueError):
                confidence = 0


            confidence = max(
                0,
                min(100, confidence)
            )


            # -----------------------------------------------
            # Generate fallback finding ID
            # -----------------------------------------------

            finding_id = item.get(
                "finding_id"
            )

            if not finding_id:

                finding_id = (
                    f"FINDING-{index:03d}"
                )


            # -----------------------------------------------
            # Force status to PROPOSED
            # -----------------------------------------------

            status = "PROPOSED"


            # -----------------------------------------------
            # Build Finding
            # -----------------------------------------------

            try:

                finding = Finding(

                    finding_id=finding_id,

                    vulnerability=item.get(
                        "vulnerability",
                        "Potential Security Issue"
                    ),

                    file=item.get(
                        "file",
                        file_path
                    ),

                    line_start=item.get(
                        "line_start"
                    ),

                    line_end=item.get(
                        "line_end"
                    ),

                    parameter=item.get(
                        "parameter"
                    ),

                    description=item.get(
                        "description",
                        ""
                    ),

                    confidence=confidence,

                    status=status
                )


                findings.append(
                    finding
                )


            except Exception as exc:

                print()
                print(
                    "Could not create Finding object:"
                )

                print(exc)

                print(
                    "Skipping this individual finding."
                )


        return findings