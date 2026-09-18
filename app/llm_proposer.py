import json
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import errors


load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError(
        "GEMINI_API_KEY was not found. "
        "Please check your .env file."
    )

client = genai.Client(api_key=api_key)


def clean_json_output(raw_output):
    """
    Remove Markdown code fences if Gemini adds them
    and convert the response into Python data.
    """

    cleaned = raw_output.strip()

    cleaned = cleaned.replace("```json", "")
    cleaned = cleaned.replace("```", "")
    cleaned = cleaned.strip()

    return json.loads(cleaned)


def validate_proposal(proposal):
    """
    Make sure Gemini returned the fields our pipeline expects.
    """

    required_fields = {
        "finding_type",
        "parameter",
        "description",
        "status"
    }

    missing_fields = required_fields - set(
        proposal.keys()
    )

    if missing_fields:
        raise ValueError(
            "Gemini response is missing required fields: "
            + ", ".join(sorted(missing_fields))
        )

    if proposal.get("status") != "PROPOSED":
        proposal["status"] = "PROPOSED"

    return proposal


def propose_finding(max_attempts=3, retry_delay=3):
    """
    Use the real Gemini API to propose a possible security finding.

    Gemini only proposes the finding.
    It does not confirm the vulnerability.

    Temporary Gemini service errors are retried automatically.
    """

    prompt = """
You are assisting with an authorised local application-security lab.

Target application:
DVWA running locally.

Context:
- Endpoint: /vulnerabilities/sqli/
- User-controlled parameter: id
- DVWA is an intentionally vulnerable training application.
- Testing is restricted to the local lab only.

Your job is ONLY to propose a possible security finding.

Do not say that the vulnerability is confirmed.
Another component will collect runtime evidence and verify the finding.

Return ONLY valid JSON using exactly this structure:

{
  "finding_type": "...",
  "parameter": "...",
  "description": "...",
  "status": "PROPOSED"
}
"""

    for attempt in range(1, max_attempts + 1):

        try:
            print(
                f"Gemini proposal attempt "
                f"{attempt}/{max_attempts}..."
            )

            response = client.models.generate_content(
                model="gemini-3.7-flash",
                contents=prompt
            )

            if not response.text:
                raise ValueError(
                    "Gemini returned an empty response."
                )

            proposal = clean_json_output(
                response.text
            )

            proposal = validate_proposal(
                proposal
            )

            print("Gemini proposal received.")

            return proposal

        except errors.ServerError as exc:

            status_code = getattr(
                exc,
                "code",
                None
            )

            print(
                f"Gemini service error "
                f"on attempt {attempt}: "
                f"{exc}"
            )

            if attempt < max_attempts:
                print(
                    f"Waiting {retry_delay} seconds "
                    "before retrying..."
                )

                time.sleep(
                    retry_delay
                )

            else:
                raise RuntimeError(
                    "Gemini is temporarily unavailable "
                    "after multiple attempts. "
                    "No proposal was generated."
                ) from exc

        except json.JSONDecodeError as exc:

            raise RuntimeError(
                "Gemini responded, but the response "
                "was not valid JSON."
            ) from exc

        except Exception as exc:

            raise RuntimeError(
                f"Gemini proposal stage failed: {exc}"
            ) from exc


if __name__ == "__main__":

    try:
        proposal = propose_finding()

        print("\nGEMINI PROPOSED FINDING")
        print("--------------------------------")

        for key, value in proposal.items():
            print(f"{key}: {value}")

    except RuntimeError as exc:

        print("\nGEMINI PROPOSAL FAILED")
        print("--------------------------------")
        print(exc)