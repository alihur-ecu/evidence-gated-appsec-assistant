from __future__ import annotations

import requests

from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.target import build_dynamic_target


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.headers = {}

    def get(
        self,
        url,
        timeout=None,
        allow_redirects=True,
    ):
        self.calls.append(url)

        response = self.responses.get(url)

        if isinstance(
            response,
            requests.RequestException,
        ):
            raise response

        if response is None:
            raise AssertionError(
                f"Unexpected request: {url}"
            )

        return response


def make_response(
    url,
    body,
    *,
    status=200,
    content_type="text/html; charset=utf-8",
    headers=None,
    cookies=None,
    history=None,
):
    response = requests.Response()

    response.status_code = status
    response.url = url
    response._content = body.encode(
        "utf-8"
    )
    response.encoding = "utf-8"
    response.headers["Content-Type"] = (
        content_type
    )

    for name, value in (headers or {}).items():
        response.headers[name] = value

    for name, value in (cookies or {}).items():
        response.cookies.set(name, value)

    response.history = list(history or [])

    request = requests.Request(
        "GET",
        url,
    )

    response.request = request.prepare()

    return response


def test_discovers_initial_page():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                "<html><title>Home</title></html>",
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.pages) == 1
    assert result.pages[0].title == "Home"
    assert result.pages[0].status_code == 200


def test_discovers_and_crawls_same_origin_link():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                '<a href="/products">Products</a>',
            ),
        "https://example.test/products":
            make_response(
                "https://example.test/products",
                "<html>Products</html>",
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.pages) == 2

    assert (
        "https://example.test/products"
        in session.calls
    )


def test_does_not_crawl_external_link():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                (
                    '<a href="https://external.test/page">'
                    "External"
                    "</a>"
                ),
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert (
        "https://external.test/page"
        in result.external_links
    )

    assert (
        "https://external.test/page"
        not in session.calls
    )


def test_discovers_query_parameter():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                '<a href="/search?q=test">Search</a>',
            ),
        "https://example.test/search?q=test":
            make_response(
                "https://example.test/search?q=test",
                "<html>Results</html>",
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    parameter_names = {
        parameter.name
        for parameter in result.parameters
    }

    assert "q" in parameter_names


def test_discovers_get_form():
    target = build_dynamic_target(
        "https://example.test"
    )

    html = """
    <form action="/search" method="get">
        <input name="q" type="text">
        <select name="category">
            <option>All</option>
        </select>
        <button>Search</button>
    </form>
    """

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                html,
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.forms) == 1

    form = result.forms[0]

    assert form.method == "GET"
    assert form.action_url == (
        "https://example.test/search"
    )

    assert {
        parameter.name
        for parameter in form.parameters
    } == {
        "q",
        "category",
    }


def test_discovers_post_form_without_submitting_it():
    target = build_dynamic_target(
        "https://example.test"
    )

    html = """
    <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
    </form>
    """

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                html,
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    form = result.forms[0]

    assert form.method == "POST"

    assert {
        parameter.name
        for parameter in form.parameters
    } == {
        "username",
        "password",
    }

    assert session.calls == [
        "https://example.test/"
    ]


def test_ignores_javascript_mailto_and_tel_links():
    target = build_dynamic_target(
        "https://example.test"
    )

    html = """
    <a href="javascript:void(0)">JS</a>
    <a href="mailto:test@example.test">Mail</a>
    <a href="tel:123456">Phone</a>
    """

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                html,
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.pages) == 1
    assert result.external_links == []


def test_respects_max_pages():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                (
                    '<a href="/one">One</a>'
                    '<a href="/two">Two</a>'
                ),
            ),
        "https://example.test/one":
            make_response(
                "https://example.test/one",
                "<html>One</html>",
            ),
        "https://example.test/two":
            make_response(
                "https://example.test/two",
                "<html>Two</html>",
            ),
    })

    result = DynamicDiscovery(
        session=session,
        max_pages=2,
    ).discover(target)

    assert len(result.pages) == 2
    assert len(session.calls) == 2


def test_records_request_error_and_continues():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            requests.ConnectionError(
                "connection failed"
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.pages) == 0
    assert len(result.errors) == 1

    assert (
        "connection failed"
        in result.errors[0]["error"]
    )


def test_does_not_parse_non_html_response():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                '{"ok": true}',
                content_type="application/json",
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    assert len(result.pages) == 1
    assert len(result.forms) == 0


def test_serialises_discovery_summary():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                """
                <form action="/search" method="get">
                    <input name="q">
                </form>
                """,
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    payload = result.to_dict()

    assert payload["summary"]["pages_discovered"] == 1
    assert payload["summary"]["forms_discovered"] == 1
    assert payload["summary"]["parameters_discovered"] == 1


def test_records_generic_http_response_metadata():
    target = build_dynamic_target(
        "https://example.test"
    )

    response = make_response(
        "https://example.test/",
        "<html><title>Portal</title></html>",
        headers={
            "X-Custom-Observation": "present",
            "Cache-Control": "no-store",
        },
        cookies={
            "session": "secret-value",
        },
        history=[
            make_response(
                "https://example.test/start",
                "",
                status=302,
            )
        ],
    )

    session = FakeSession({
        "https://example.test/": response,
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    page = result.pages[0]

    assert page.status_code == 200
    assert page.title == "Portal"
    assert page.redirect_count == 1
    assert "Content-Type" in page.response_header_names
    assert "X-Custom-Observation" in page.response_header_names
    assert "session" in page.cookie_names


def test_serialised_page_metadata_does_not_expose_cookie_values():
    target = build_dynamic_target(
        "https://example.test"
    )

    session = FakeSession({
        "https://example.test/":
            make_response(
                "https://example.test/",
                "<html>Home</html>",
                cookies={
                    "session": "do-not-forward",
                },
            ),
    })

    result = DynamicDiscovery(
        session=session
    ).discover(target)

    page = result.to_dict()["pages"][0]

    assert page["cookie_names"] == ["session"]
    assert "do-not-forward" not in str(page)
