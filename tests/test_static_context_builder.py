from app.static_analysis.collector import SourceFile
from app.static_analysis.context_builder import (
    StaticContextBuilder,
)


def make_source_file(
    *,
    path: str,
    language: str,
    code: str,
) -> SourceFile:
    return SourceFile(
        filename=path.split("/")[-1],
        relative_path=path,
        extension=".py",
        language=language,
        source_code=code,
        line_count=len(code.splitlines()),
        size_bytes=len(code.encode("utf-8")),
    )


def test_small_file_remains_single_chunk():
    source = make_source_file(
        path="app/users.py",
        language="Python",
        code=(
            "import sqlite3\n"
            "\n"
            "def get_user(user_id):\n"
            "    return user_id\n"
        ),
    )

    result = StaticContextBuilder(
        max_chunk_chars=1000,
    ).build([source])

    assert result.chunk_count == 1

    chunk = result.chunks[0]

    assert chunk.source_file == "app/users.py"
    assert chunk.start_line == 1
    assert chunk.end_line == 4
    assert chunk.source_code == source.source_code

    assert result.files_discovered == 1
    assert result.files_selected == 1
    assert result.empty_files == 0
    assert result.files_excluded_by_budget == 0
    assert result.truncated is False


def test_large_file_produces_multiple_chunks_with_provenance():
    code = "".join(
        f"line_{number} = {number}\n"
        for number in range(1, 101)
    )

    source = make_source_file(
        path="src/large.py",
        language="Python",
        code=code,
    )

    result = StaticContextBuilder(
        max_chunk_chars=250,
        overlap_lines=3,
        max_analysis_chars=10_000,
    ).build([source])

    assert result.chunk_count > 1

    first = result.chunks[0]
    second = result.chunks[1]

    assert first.source_file == "src/large.py"
    assert second.source_file == "src/large.py"

    assert first.start_line == 1

    # Adjacent chunks should overlap.
    assert second.start_line <= first.end_line

    # But the builder must always make forward progress.
    assert second.start_line > first.start_line

    for chunk in result.chunks:
        assert chunk.start_line <= chunk.end_line

        assert chunk.chunk_id == (
            f"{chunk.source_file}:"
            f"{chunk.start_line}-{chunk.end_line}"
        )


def test_chunks_never_mix_source_files():
    first_source = make_source_file(
        path="app/a.py",
        language="Python",
        code="a = 1\n" * 50,
    )

    second_source = make_source_file(
        path="app/b.py",
        language="Python",
        code="b = 2\n" * 50,
    )

    result = StaticContextBuilder(
        max_chunk_chars=100,
        overlap_lines=2,
        max_analysis_chars=20_000,
    ).build(
        [
            first_source,
            second_source,
        ]
    )

    source_names = {
        chunk.source_file
        for chunk in result.chunks
    }

    assert source_names == {
        "app/a.py",
        "app/b.py",
    }

    for chunk in result.chunks:
        assert chunk.source_file in {
            "app/a.py",
            "app/b.py",
        }


def test_global_character_budget_is_enforced_and_reported():
    first_source = make_source_file(
        path="a.py",
        language="Python",
        code="a = 1\n" * 100,
    )

    second_source = make_source_file(
        path="b.py",
        language="Python",
        code="b = 2\n" * 100,
    )

    result = StaticContextBuilder(
        max_chunk_chars=200,
        overlap_lines=0,
        max_analysis_chars=500,
        max_analysis_files=100,
    ).build(
        [
            first_source,
            second_source,
        ]
    )

    assert result.selected_chars <= 500
    assert result.truncated is True
    assert result.truncation_reason is not None
    assert result.files_excluded_by_budget >= 1


def test_global_file_budget_is_enforced_and_reported():
    sources = [
        make_source_file(
            path=f"src/file_{number}.py",
            language="Python",
            code=f"value = {number}\n",
        )
        for number in range(10)
    ]

    result = StaticContextBuilder(
        max_chunk_chars=1000,
        max_analysis_chars=100_000,
        max_analysis_files=3,
    ).build(sources)

    assert result.files_discovered == 10
    assert result.files_selected == 3
    assert result.empty_files == 0
    assert result.files_excluded_by_budget == 7
    assert result.truncated is True

    assert (
        result.truncation_reason
        == (
            "Maximum number of source files selected "
            "for analysis was reached."
        )
    )


def test_build_order_is_deterministic():
    a = make_source_file(
        path="z/file.py",
        language="Python",
        code="z = 1\n",
    )

    b = make_source_file(
        path="a/file.py",
        language="Python",
        code="a = 1\n",
    )

    result = StaticContextBuilder().build(
        [a, b]
    )

    assert result.chunks[0].source_file == "a/file.py"
    assert result.chunks[1].source_file == "z/file.py"


def test_empty_files_are_reported_separately():
    source_with_code = make_source_file(
        path="app/main.py",
        language="Python",
        code=(
            "def main():\n"
            "    return True\n"
        ),
    )

    empty_source = make_source_file(
        path="app/__init__.py",
        language="Python",
        code="",
    )

    result = StaticContextBuilder().build(
        [
            source_with_code,
            empty_source,
        ]
    )

    assert result.files_discovered == 2
    assert result.files_selected == 1

    assert result.empty_files == 1

    assert result.files_excluded_by_budget == 0

    assert result.chunk_count == 1
    assert result.truncated is False

    assert (
        result.chunks[0].source_file
        == "app/main.py"
    )