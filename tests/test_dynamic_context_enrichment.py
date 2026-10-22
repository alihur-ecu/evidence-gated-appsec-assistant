import requests

from app.dynamic_analysis.context_builder import DynamicContextBuilder
from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.target import build_dynamic_target


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.headers = {}

    def get(self, url, **kwargs):
        return self.response


def make_response(url, body, content_type="application/json; charset=utf-8"):
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    response.headers["Content-Type"] = content_type
    response.history = []
    return response


def test_discovery_preserves_query_value_and_bounded_response_excerpt():
    url = "https://example.test/search?q=apple"
    body = '{"status":"success","data":[{"name":"Apple Juice"}]}'
    result = DynamicDiscovery(
        session=FakeSession(make_response(url, body)),
        max_response_excerpt_chars=30,
    ).discover(build_dynamic_target(url))

    assert result.endpoints[0].parameters[0].name == "q"
    assert result.endpoints[0].parameters[0].observed_value == "apple"
    assert result.pages[0].response_excerpt
    assert len(result.pages[0].response_excerpt) <= 31


def test_context_renders_observed_value_and_response_excerpt():
    url = "https://example.test/search?q=apple"
    body = '{"status":"success","data":[{"name":"Apple Juice"}]}'
    discovery = DynamicDiscovery(
        session=FakeSession(make_response(url, body)),
    ).discover(build_dynamic_target(url))

    context = DynamicContextBuilder().build(discovery).contexts[0]

    assert "observed_value='apple'" in context.context_text
    assert "Bounded response excerpt (observed, not verified):" in context.context_text
    assert '"status":"success"' in context.context_text
    assert "Security status: NOT VERIFIED" in context.context_text


def test_html_excerpt_uses_visible_text_and_does_not_forward_scripts():
    url = "https://example.test/page?q=hello"
    body = (
        "<html><head><title>Portal</title>"
        "<script>secretScriptValue()</script></head>"
        "<body><h1>Welcome</h1><p>Observed content</p></body></html>"
    )
    discovery = DynamicDiscovery(
        session=FakeSession(make_response(url, body, "text/html")),
    ).discover(build_dynamic_target(url))

    excerpt = discovery.pages[0].response_excerpt
    assert "Welcome" in excerpt
    assert "Observed content" in excerpt
    assert "secretScriptValue" not in excerpt


def test_binary_response_does_not_create_excerpt():
    url = "https://example.test/file?q=1"
    discovery = DynamicDiscovery(
        session=FakeSession(make_response(url, "binary-data", "application/octet-stream")),
    ).discover(build_dynamic_target(url))

    assert discovery.pages[0].response_excerpt is None
