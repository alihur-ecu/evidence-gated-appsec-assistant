from app.models.finding import Finding, FindingType, FindingStatus


def test_finding_roundtrip():
    f = Finding(
        finding_type=FindingType.SQL_INJECTION,
        endpoint="/vulnerabilities/sqli/",
        parameter="id",
        method="GET",
        explanation="The id parameter appears to be concatenated into a SQL query.",
        confidence=0.7,
    )
    assert f.status == FindingStatus.PROPOSED

    data = f.to_dict()
    f2 = Finding.from_dict(data)
    assert f2.finding_id == f.finding_id
    assert f2.finding_type == FindingType.SQL_INJECTION

    print(data)


if __name__ == "__main__":
    test_finding_roundtrip()
    print("OK")