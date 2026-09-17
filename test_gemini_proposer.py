from app.llm.proposer import GeminiSecurityProposer


print("=" * 40)
print("GEMINI STATIC SECURITY ANALYSIS")
print("=" * 40)


# Test file
file_path = r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities\sqli\source\low.php"


# Read PHP source
with open(
    file_path,
    "r",
    encoding="utf-8",
    errors="ignore"
) as file:
    source_code = file.read()


# Create Gemini analyzer
analyzer = GeminiSecurityProposer()


# Analyze
findings = analyzer.analyze(
    file_path,
    source_code
)


for finding in findings:

    print("-" * 40)

    print(
        "Finding ID:",
        finding.finding_id
    )

    print(
        "Vulnerability:",
        finding.vulnerability
    )

    print(
        "File:",
        finding.file_path
    )

    print(
        "Parameter/Input:",
        finding.parameter
    )

    print(
        "Why vulnerable:",
        finding.description
    )

    print(
        "Confidence:",
        finding.confidence
    )

    print(
        "Status:",
        finding.status
    )