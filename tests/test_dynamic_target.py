import pytest

from app.dynamic_analysis.target import (
    DynamicTarget,
    InvalidDynamicTarget,
    build_dynamic_target,
)


def test_builds_https_target():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert isinstance(target, DynamicTarget)
    assert target.base_url == "https://example.com/"
    assert target.origin == "https://example.com"
    assert target.scheme == "https"
    assert target.hostname == "example.com"
    assert target.port is None
    assert target.start_path == "/"


def test_adds_https_when_scheme_is_missing():
    target = build_dynamic_target(
        "example.com"
    )

    assert target.base_url == "https://example.com/"
    assert target.scheme == "https"


def test_preserves_http_when_explicit():
    target = build_dynamic_target(
        "http://example.com"
    )

    assert target.base_url == "http://example.com/"
    assert target.origin == "http://example.com"


def test_preserves_custom_port():
    target = build_dynamic_target(
        "http://localhost:4280"
    )

    assert target.hostname == "localhost"
    assert target.port == 4280
    assert target.origin == "http://localhost:4280"


def test_preserves_start_path():
    target = build_dynamic_target(
        "https://example.com/application/login"
    )

    assert (
        target.base_url
        == "https://example.com/application/login"
    )

    assert target.start_path == "/application/login"


def test_removes_fragment():
    target = build_dynamic_target(
        "https://example.com/app#section"
    )

    assert target.base_url == "https://example.com/app"


def test_preserves_query():
    target = build_dynamic_target(
        "https://example.com/search?q=test"
    )

    assert (
        target.base_url
        == "https://example.com/search?q=test"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
    ],
)
def test_rejects_empty_target(value):
    with pytest.raises(
        InvalidDynamicTarget
    ):
        build_dynamic_target(value)


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "file:///tmp/test",
        "javascript:alert(1)",
    ],
)
def test_rejects_unsupported_scheme(value):
    with pytest.raises(
        InvalidDynamicTarget
    ):
        build_dynamic_target(value)


def test_rejects_embedded_credentials():
    with pytest.raises(
        InvalidDynamicTarget
    ):
        build_dynamic_target(
            "https://user:password@example.com"
        )


def test_rejects_invalid_port():
    with pytest.raises(
        InvalidDynamicTarget
    ):
        build_dynamic_target(
            "https://example.com:notaport"
        )


def test_same_origin_accepts_same_host():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert target.is_same_origin(
        "https://example.com/login"
    )


def test_same_origin_accepts_relative_url():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert target.is_same_origin(
        "/login"
    )


def test_same_origin_rejects_different_host():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert not target.is_same_origin(
        "https://other.example/login"
    )


def test_same_origin_rejects_different_scheme():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert not target.is_same_origin(
        "http://example.com/login"
    )


def test_default_https_port_matches_explicit_443():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert target.is_same_origin(
        "https://example.com:443/login"
    )


def test_different_port_is_not_same_origin():
    target = build_dynamic_target(
        "https://example.com"
    )

    assert not target.is_same_origin(
        "https://example.com:8443/login"
    )