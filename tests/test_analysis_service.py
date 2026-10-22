from pathlib import Path
from zipfile import ZipFile

from app.analysis.analysis_service import (
    run_static_analysis,
)


def create_test_archive(
    tmp_path: Path,
) -> Path:
  
    project_directory = (
        tmp_path / "sample_project"
    )

    project_directory.mkdir()

    source_directory = (
        project_directory / "app"
    )

    source_directory.mkdir()

    (
        source_directory / "__init__.py"
    ).write_text(
        "",
        encoding="utf-8",
    )

    (
        source_directory / "users.py"
    ).write_text(
        (
            "def get_user(user_id):\n"
            "    return user_id\n"
        ),
        encoding="utf-8",
    )

    (
        source_directory / "views.py"
    ).write_text(
        (
            "def render_profile(name):\n"
            "    return name\n"
        ),
        encoding="utf-8",
    )

    archive_path = (
        tmp_path / "sample_project.zip"
    )

    with ZipFile(
        archive_path,
        "w",
    ) as archive:

        for path in (
            project_directory.rglob("*")
        ):
            if not path.is_file():
                continue

            archive.write(
                path,
                path.relative_to(
                    project_directory
                ),
            )

    return archive_path


def test_static_source_provider_builds_bounded_context(
    tmp_path,
    monkeypatch,
):
  

    archive_path = create_test_archive(
        tmp_path
    )

    monkeypatch.setenv(
        "ANALYSIS_PROVIDER",
        "static_source",
    )

    monkeypatch.setenv(
        "LLM_PROVIDER",
        "none",
    )

    result = run_static_analysis(
        source_path=str(
            archive_path
        ),
        original_filename=(
            "sample_project.zip"
        ),
        application_name=(
            "Generic Test Application"
        ),
    )

    assert result["analysis_mode"] == (
        "STATIC"
    )

    assert result["scan_type"] == (
        "STATIC"
    )

    assert result["provider"] == (
        "STATIC_SOURCE"
    )

    assert result["analysis_id"].startswith(
        "A-"
    )

    assert (
        result["source_summary"][
            "source_files"
        ]
        == 3
    )

    coverage = result[
        "context_coverage"
    ]

    assert coverage[
        "files_discovered"
    ] == 3

    assert coverage[
        "files_selected"
    ] == 2

    assert coverage[
        "empty_files"
    ] == 1

    assert coverage[
        "files_excluded_by_budget"
    ] == 0

    assert coverage[
        "chunks_created"
    ] == 2

    assert coverage[
        "truncated"
    ] is False

    assert len(
        result["source_context"]
    ) == 2

    for chunk in result[
        "source_context"
    ]:
        assert "chunk_id" in chunk
        assert "source_file" in chunk
        assert "start_line" in chunk
        assert "end_line" in chunk
        assert "source_code" in chunk
        assert "char_count" in chunk

    # Ingestion and context building must never invent findings.
    assert result["findings"] == []

    assert result["aggregation"] == {
        "proposals_received": 0,
        "proposals_retained": 0,
        "duplicates_merged": 0,
    }

    assert result[
        "proposal_provider"
    ] == "NONE"


def test_mock_provider_remains_compatible(
    tmp_path,
    monkeypatch,
):
    """
    The existing development mock must continue working after the
    aggregation layer is introduced.

    The mock analysis path does not require a live LLM.
    """

    mock_archive = (
        tmp_path
        / "mock_vulnerable_shop.zip"
    )

    mock_archive.write_bytes(
        b"development fixture"
    )

    monkeypatch.setenv(
        "ANALYSIS_PROVIDER",
        "mock",
    )

    monkeypatch.setenv(
        "LLM_PROVIDER",
        "none",
    )

    result = run_static_analysis(
        source_path=str(
            mock_archive
        ),
        original_filename=(
            "mock_vulnerable_shop.zip"
        ),
        application_name=(
            "Mock Vulnerable Shop"
        ),
    )

    assert result["provider"] == "MOCK"

    assert result[
        "analysis_id"
    ].startswith("A-")

    assert len(
        result["findings"]
    ) > 0

    assert (
        result["aggregation"][
            "proposals_received"
        ]
        == len(result["findings"])
    )

    assert (
        result["aggregation"][
            "proposals_retained"
        ]
        == len(result["findings"])
    )

    assert (
        result["aggregation"][
            "duplicates_merged"
        ]
        == 0
    )


def test_environment_provider_selection_is_isolated(
    tmp_path,
    monkeypatch,
):


    monkeypatch.setenv(
        "LLM_PROVIDER",
        "none",
    )

    archive_path = create_test_archive(
        tmp_path
    )

    monkeypatch.setenv(
        "ANALYSIS_PROVIDER",
        "static_source",
    )

    static_result = run_static_analysis(
        source_path=str(
            archive_path
        ),
        original_filename=(
            "sample_project.zip"
        ),
        application_name="Static",
    )

    assert (
        static_result["provider"]
        == "STATIC_SOURCE"
    )

    assert (
        static_result["proposal_provider"]
        == "NONE"
    )

    mock_archive = (
        tmp_path
        / "mock_vulnerable_shop.zip"
    )

    mock_archive.write_bytes(
        b"development fixture"
    )

    monkeypatch.setenv(
        "ANALYSIS_PROVIDER",
        "mock",
    )

    mock_result = run_static_analysis(
        source_path=str(
            mock_archive
        ),
        original_filename=(
            "mock_vulnerable_shop.zip"
        ),
        application_name="Mock",
    )

    assert (
        mock_result["provider"]
        == "MOCK"
    )