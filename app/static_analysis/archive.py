"""
Safe archive ingestion for static source-code analysis.

Uploaded ZIP files are treated as untrusted input.

This module validates and extracts ZIP archives into an isolated
directory before the StaticSourceCollector processes their contents.
"""

from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_MAX_TOTAL_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 200


class ArchiveValidationError(ValueError):
    """Raised when an uploaded archive fails safety validation."""


@dataclass(frozen=True)
class ExtractionResult:
    """Information about a successfully extracted project archive."""

    destination: Path
    extracted_files: int
    total_uncompressed_bytes: int


class SafeZipExtractor:
    """
    Validate and safely extract an arbitrary source-code ZIP archive.

    Security controls:
    - ZIP format validation
    - path traversal prevention
    - absolute path rejection
    - file-count limit
    - per-file uncompressed-size limit
    - total uncompressed-size limit
    - suspicious compression-ratio detection
    """

    def __init__(
        self,
        *,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
    ) -> None:
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.max_total_size = max_total_size
        self.max_compression_ratio = max_compression_ratio

    def extract(
        self,
        archive_path: str | Path,
        destination: str | Path,
    ) -> ExtractionResult:
        archive = Path(archive_path).expanduser().resolve()
        output = Path(destination).expanduser().resolve()

        if not archive.exists():
            raise FileNotFoundError(
                f"Uploaded archive does not exist: {archive}"
            )

        if not archive.is_file():
            raise ArchiveValidationError(
                "The supplied archive path is not a file."
            )

        if not zipfile.is_zipfile(archive):
            raise ArchiveValidationError(
                "The uploaded file is not a valid ZIP archive."
            )

        output.mkdir(parents=True, exist_ok=True)

        extracted_files = 0
        total_size = 0

        try:
            with zipfile.ZipFile(archive, "r") as zip_file:
                members = zip_file.infolist()

                regular_files = [
                    member
                    for member in members
                    if not member.is_dir()
                ]

                if len(regular_files) > self.max_files:
                    raise ArchiveValidationError(
                        "Archive contains too many files "
                        f"({len(regular_files)} > {self.max_files})."
                    )

                # Validate the complete archive before extracting anything.
                for member in members:
                    self._validate_member(member)

                    if member.is_dir():
                        continue

                    total_size += member.file_size

                    if member.file_size > self.max_file_size:
                        raise ArchiveValidationError(
                            f"Archive member '{member.filename}' exceeds "
                            "the maximum allowed file size."
                        )

                    if total_size > self.max_total_size:
                        raise ArchiveValidationError(
                            "Archive exceeds the maximum total "
                            "uncompressed size."
                        )

                    self._validate_compression_ratio(member)

                # Only extract after every member has passed validation.
                for member in members:
                    member_path = self._safe_member_path(
                        output,
                        member.filename,
                    )

                    if member.is_dir():
                        member_path.mkdir(
                            parents=True,
                            exist_ok=True,
                        )
                        continue

                    member_path.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    with zip_file.open(member, "r") as source:
                        with member_path.open("wb") as target:
                            shutil.copyfileobj(source, target)

                    extracted_files += 1

        except Exception:
            # Do not leave a partially extracted project behind when
            # validation or extraction fails.
            shutil.rmtree(output, ignore_errors=True)
            raise

        return ExtractionResult(
            destination=output,
            extracted_files=extracted_files,
            total_uncompressed_bytes=total_size,
        )

    def _validate_member(
        self,
        member: zipfile.ZipInfo,
    ) -> None:
        filename = member.filename.replace("\\", "/")

        if not filename:
            raise ArchiveValidationError(
                "Archive contains an unnamed member."
            )

        path = PurePosixPath(filename)

        if path.is_absolute():
            raise ArchiveValidationError(
                f"Absolute archive path rejected: {filename}"
            )

        if ".." in path.parts:
            raise ArchiveValidationError(
                f"Archive path traversal rejected: {filename}"
            )

        # Reject Windows drive-like paths such as C:/...
        if path.parts and ":" in path.parts[0]:
            raise ArchiveValidationError(
                f"Drive-qualified archive path rejected: {filename}"
            )

        # ZIP entries can encode Unix file types in external_attr.
        # Symbolic links are not required for source ingestion and can
        # complicate containment guarantees, so reject them.
        unix_mode = (member.external_attr >> 16) & 0xFFFF
        file_type = unix_mode & 0o170000

        if file_type == 0o120000:
            raise ArchiveValidationError(
                f"Symbolic link rejected: {filename}"
            )

    def _validate_compression_ratio(
        self,
        member: zipfile.ZipInfo,
    ) -> None:
        if member.file_size == 0:
            return

        compressed_size = member.compress_size

        if compressed_size == 0:
            raise ArchiveValidationError(
                f"Suspicious compressed member: {member.filename}"
            )

        ratio = member.file_size / compressed_size

        if ratio > self.max_compression_ratio:
            raise ArchiveValidationError(
                f"Suspicious compression ratio for "
                f"'{member.filename}': {ratio:.1f}:1"
            )

    @staticmethod
    def _safe_member_path(
        destination: Path,
        filename: str,
    ) -> Path:
        relative = PurePosixPath(
            filename.replace("\\", "/")
        )

        candidate = destination.joinpath(
            *relative.parts
        ).resolve()

        try:
            candidate.relative_to(destination)
        except ValueError as exc:
            raise ArchiveValidationError(
                f"Archive member escapes extraction directory: "
                f"{filename}"
            ) from exc

        return candidate