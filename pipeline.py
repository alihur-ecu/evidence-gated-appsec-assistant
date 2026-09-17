from app.static_analysis.collector import StaticSourceCollector
from app.llm.proposer import GeminiSecurityProposer


DVWA_PATH = r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities"


print("=" * 50)
print("DVWA GEMINI STATIC SECURITY SCANNER")
print("=" * 50)


# 1. Collect PHP files

collector = StaticSourceCollector(
    DVWA_PATH
)

files = collector.collect_php_files()


print(f"\nTotal PHP files collected: {len(files)}")


# 2. Initialize Gemini

analyzer = GeminiSecurityProposer()


all_findings = []


# 3. Analyze files

for index, file in enumerate(files):

    print("\nAnalyzing:")
    print(file["file_path"])


    findings = analyzer.analyze(
        file["file_path"],
        file["source_code"]
    )


    all_findings.extend(findings)



print("\n================================")
print("ANALYSIS COMPLETED")
print("================================")


print(
    f"Total findings: {len(all_findings)}"
)


for finding in all_findings[:10]:

    print("\n----------------")
    print(finding)