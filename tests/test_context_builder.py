from app.context.context_builder import build_context


def test_build_context_against_dvwa():
    context = build_context(
        target_name="DVWA",
        base_url="http://localhost:4280",
        endpoint="/vulnerabilities/sqli/",
        method="GET",
        parameters={"id": "1", "Submit": "Submit"},
    )

    assert context["target"] == "DVWA"
    assert context["baseline_status"] == 200
    assert "response_excerpt" in context

    print(context)


if __name__ == "__main__":
    test_build_context_against_dvwa()
    print("OK")
