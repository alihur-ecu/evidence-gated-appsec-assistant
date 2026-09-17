from app.static_analysis.collector import StaticSourceCollector


print("=" * 40)
print("DVWA STATIC SOURCE COLLECTION")
print("=" * 40)


# Actual DVWA vulnerability source folder
DVWA_PATH = r"C:\Users\ZUMAL\Documents\DVWA\vulnerabilities"


# Create collector
collector = StaticSourceCollector(
    DVWA_PATH
)


# Collect all PHP files
files = collector.collect_php_files()


print()
print(f"PHP files found: {len(files)}")


# Show collected files
for file in files[:10]:

    print("\n" + "-" * 40)
    print("FILE:", file["file_path"])
    print("-" * 40)

    # Print first 1000 characters of code
    print(
        file["source_code"][:1000]
    )