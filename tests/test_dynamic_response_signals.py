from app.dynamic_analysis.evidence.response_signals import (
    ResponseSignalExtractor,
)


def test_no_error_in_normal_html():
    extractor = ResponseSignalExtractor()

    result = extractor.extract(
        "<html><body>Normal page</body></html>"
    )

    assert result.error_detected is False
    assert result.error_family is None
    assert result.error_signature is None


def test_detects_sql_syntax_error():
    extractor = ResponseSignalExtractor()

    result = extractor.extract(
        "You have an error in your SQL syntax; "
        "check the manual that corresponds to "
        "your database server version."
    )

    assert result.error_detected is True
    assert result.error_family == "SQL_SYNTAX"
    assert result.error_signature == (
        "sql_syntax_error"
    )


def test_detects_postgresql_error():
    extractor = ResponseSignalExtractor()

    result = extractor.extract(
        "PostgreSQL ERROR: syntax error "
        "at or near quote"
    )

    assert result.error_detected is True
    assert result.error_family == "POSTGRESQL"


def test_detects_oracle_error():
    extractor = ResponseSignalExtractor()

    result = extractor.extract(
        "ORA-00933: SQL command not properly ended"
    )

    assert result.error_detected is True
    assert result.error_family == "ORACLE"


def test_empty_response_is_not_error():
    extractor = ResponseSignalExtractor()

    result = extractor.extract("")

    assert result.error_detected is False


def test_extraction_is_bounded():
    extractor = ResponseSignalExtractor(
        max_text_chars=20
    )

    result = extractor.extract(
        ("A" * 30)
        + " You have an error in your SQL syntax"
    )

    assert result.error_detected is False


def test_invalid_max_text_chars_rejected():
    try:
        ResponseSignalExtractor(
            max_text_chars=0
        )
    except ValueError as exc:
        assert (
            "max_text_chars must be greater than zero"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected ValueError"
        )