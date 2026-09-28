"""Target-neutral extraction of deterministic response signals."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ResponseSignals:
    """Bounded signals extracted from one HTTP response."""

    error_detected: bool
    error_family: str | None = None
    error_signature: str | None = None


class ResponseSignalExtractor:
    """
    Extract deterministic signals from HTTP response text.

    The extractor is intentionally target-neutral:
    - no DVWA-specific behaviour
    - no endpoint-specific behaviour
    - no parameter-specific behaviour
    - no vulnerability decision

    It only records observable response characteristics.
    """

    _ERROR_PATTERNS = (
        (
            "SQL_SYNTAX",
            "sql_syntax_error",
            re.compile(
                r"(?:you have an error in your sql syntax|"
                r"sql syntax.*?error|"
                r"syntax error.*?sql)",
                re.IGNORECASE,
            ),
        ),
        (
            "MYSQL_MARIADB",
            "mysql_mariadb_error",
            re.compile(
                r"(?:mysql|mariadb).{0,120}"
                r"(?:error|exception|syntax|warning)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "POSTGRESQL",
            "postgresql_error",
            re.compile(
                r"(?:postgresql|postgres|psql).{0,120}"
                r"(?:error|exception|syntax|warning)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "MICROSOFT_SQL_SERVER",
            "mssql_error",
            re.compile(
                r"(?:sql server|microsoft ole db provider|"
                r"sqlserverexception|unclosed quotation mark)",
                re.IGNORECASE,
            ),
        ),
        (
            "ORACLE",
            "oracle_error",
            re.compile(
                r"\bORA-\d{4,5}\b",
                re.IGNORECASE,
            ),
        ),
        (
            "SQLITE",
            "sqlite_error",
            re.compile(
                r"(?:sqlite(?:3)?(?:error|exception)?|"
                r"sqlite error|sqlite exception)",
                re.IGNORECASE,
            ),
        ),
        (
            "DATABASE_GENERIC",
            "database_error",
            re.compile(
                r"(?:database error|database exception|"
                r"db exception|query failed)",
                re.IGNORECASE,
            ),
        ),
    )

    def __init__(self, *, max_text_chars: int = 100_000):
        if max_text_chars <= 0:
            raise ValueError(
                "max_text_chars must be greater than zero."
            )

        self.max_text_chars = max_text_chars

    def extract(self, text: str | None) -> ResponseSignals:
        if not text:
            return ResponseSignals(
                error_detected=False,
            )

        bounded_text = text[: self.max_text_chars]

        for family, signature, pattern in self._ERROR_PATTERNS:
            if pattern.search(bounded_text):
                return ResponseSignals(
                    error_detected=True,
                    error_family=family,
                    error_signature=signature,
                )

        return ResponseSignals(
            error_detected=False,
        )