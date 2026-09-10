import json
import os

from dotenv import load_dotenv
from google import genai


load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError(
        "GEMINI_API_KEY was not found. "
        "Please check your .env file."
    )

client = genai.Client(api_key=api_key)


def propose_finding():
    """
    Use the real Gemini API to propose a possible security finding.

    Important:
    Gemini only proposes the finding.
    It does not confirm the vulnerability.
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

    response = client.models.generate_content(
        model="gemini-3.7-flash",
        contents=prompt
    )

    raw_output = response.text.strip()

    # Remove Markdown code fences if Gemini adds them
    raw_output = raw_output.replace("```json", "")
    raw_output = raw_output.replace("```", "")
    raw_output = raw_output.strip()

    proposal = json.loads(raw_output)

    return proposal


if __name__ == "__main__":

    proposal = propose_finding()

    print("\n GEMINI PROPOSED FINDING")

    for key, value in proposal.items():
        print(f"{key}: {value}")