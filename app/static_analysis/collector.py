from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript/JSX",
    ".ts": "TypeScript",
    ".tsx": "TypeScript/TSX",
    ".php": "PHP",
    ".java": "Java",
    ".cs": "C#",
    ".go": "Go",
    ".rb": "Ruby",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++ Header",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".html": "HTML",
    ".htm": "HTML",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".sql": "SQL",
    ".graphql": "GraphQL",
    ".gql": "GraphQL",
}


IGNORED_DIRECTORIES = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
}


IGNORED_FILENAMES = {
    ".ds_store",
}


# Protect downstream analysis from unexpectedly huge individual files.
DEFAULT_MAX_FILE_SIZE = 1_000_000  # 1 MB


@dataclass(frozen=True)
class SourceFile:
    """Structured context for one discovered source file."""

    filename: str
    relative_path: str
    extension: str
    language: str
    source_code: str
    line_count: int
    size_bytes: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CollectionResult:

    root_path: str
    files: list[SourceFile]
    skipped_files: list[dict]

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_lines(self) -> int:
        return sum(item.line_count for item in self.files)

    @property
    def languages(self) -> list[str]:
        return sorted({item.language for item in self.files})

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "file_count": self.file_count,
            "total_lines": self.total_lines,
            "languages": self.languages,
            "files": [item.to_dict() for item in self.files],
            "skipped_files": list(self.skipped_files),
        }


class StaticSourceCollector:


    def __init__(
        self,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        ignored_directories: Optional[Iterable[str]] = None,
    ) -> None:
        if max_file_size <= 0:
            raise ValueError("max_file_size must be greater than zero.")

        self.max_file_size = max_file_size

        self.ignored_directories = {
            item.lower()
            for item in (
                ignored_directories
                if ignored_directories is not None
                else IGNORED_DIRECTORIES
            )
        }

    def collect(self, source_root: str | Path) -> CollectionResult:
        root = Path(source_root).expanduser().resolve()

        if not root.exists():
            raise FileNotFoundError(
                f"Static analysis source does not exist: {root}"
            )

        if not root.is_dir():
            raise ValueError(
                "StaticSourceCollector expects an extracted project directory."
            )

        files: list[SourceFile] = []
        skipped_files: list[dict] = []

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue

            relative_path = path.relative_to(root)

            if self._is_ignored_path(relative_path):
                continue

            extension = path.suffix.lower()

            if extension not in LANGUAGE_BY_EXTENSION:
                continue

            try:
                size_bytes = path.stat().st_size
            except OSError as exc:
                skipped_files.append(
                    self._skip_record(relative_path, "stat_error", str(exc))
                )
                continue

            if size_bytes > self.max_file_size:
                skipped_files.append(
                    self._skip_record(
                        relative_path,
                        "file_too_large",
                        f"{size_bytes} bytes",
                    )
                )
                continue

            if self._looks_binary(path):
                skipped_files.append(
                    self._skip_record(
                        relative_path,
                        "binary_content",
                    )
                )
                continue

            try:
                source_code = path.read_text(
                    encoding="utf-8",
                    errors="strict",
                )
            except UnicodeDecodeError:
             
                try:
                    source_code = path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                except OSError as exc:
                    skipped_files.append(
                        self._skip_record(
                            relative_path,
                            "read_error",
                            str(exc),
                        )
                    )
                    continue
            except OSError as exc:
                skipped_files.append(
                    self._skip_record(
                        relative_path,
                        "read_error",
                        str(exc),
                    )
                )
                continue

            line_count = len(source_code.splitlines())

            files.append(
                SourceFile(
                    filename=path.name,
                    relative_path=relative_path.as_posix(),
                    extension=extension,
                    language=LANGUAGE_BY_EXTENSION[extension],
                    source_code=source_code,
                    line_count=line_count,
                    size_bytes=size_bytes,
                )
            )

        return CollectionResult(
            root_path=str(root),
            files=files,
            skipped_files=skipped_files,
        )

    def _is_ignored_path(self, relative_path: Path) -> bool:
        if relative_path.name.lower() in IGNORED_FILENAMES:
            return True

        return any(
            part.lower() in self.ignored_directories
            for part in relative_path.parts[:-1]
        )

    @staticmethod
    def _looks_binary(path: Path) -> bool:
      
        try:
            with path.open("rb") as handle:
                sample = handle.read(8192)
        except OSError:
            return False

        return b"\x00" in sample

    @staticmethod
    def _skip_record(
        relative_path: Path,
        reason: str,
        detail: Optional[str] = None,
    ) -> dict:
        record = {
            "relative_path": relative_path.as_posix(),
            "reason": reason,
        }

        if detail:
            record["detail"] = detail

        return record