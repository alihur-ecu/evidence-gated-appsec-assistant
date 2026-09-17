from pathlib import Path


class StaticSourceCollector:

    def __init__(self, target_root: str):
        self.target_root = Path(target_root)


    def collect_php_files(self):

        collected_files = []

        for php_file in self.target_root.rglob("*.php"):

            try:
                source_code = php_file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )

                collected_files.append(
                    {
                        "file_path": str(php_file),
                        "source_code": add_line_numbers(source_code)
                    }
                )

            except Exception as e:
                print(
                    f"Could not read {php_file}: {e}"
                )

        return collected_files



def add_line_numbers(source_code: str) -> str:

    lines = source_code.splitlines()

    numbered_lines = []

    for number, line in enumerate(lines, start=1):

        numbered_lines.append(
            f"{number:04d} | {line}"
        )

    return "\n".join(numbered_lines)