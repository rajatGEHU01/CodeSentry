import pytest

from codesentry.analyzers.sql_analyzer import SQLAnalyzer


def analyze(source):

    return SQLAnalyzer().analyze(
        source,
        "test.sql"
    )


@pytest.mark.parametrize(
    "source,rule_id",
    [
        ("DELETE FROM users;", "SQL001"),

        ("UPDATE users SET age = 20;", "SQL002"),

        ("SELECT * FROM users;", "SQL003"),

        ("SELECT u.* FROM users u;", "SQL003"),

        (
            "SELECT a.id FROM a CROSS JOIN b;",
            "SQL004"
        ),

        ("DROP TABLE users;", "SQL005"),

        ("TRUNCATE TABLE users;", "SQL006"),

        (
            "DELETE FROM users WHERE 1 = 1;",
            "SQL009"
        ),

        (
            "UPDATE users SET age = 0 WHERE TRUE;",
            "SQL009"
        )
    ]
)
def test_unsafe_queries(source, rule_id):

    findings = analyze(source)

    assert any(
        finding.rule_id == rule_id
        for finding in findings
    )


@pytest.mark.parametrize(
    "source",
    [
        "SELECT name FROM users;",

        "SELECT COUNT(*) FROM users;",

        "DELETE FROM users WHERE id = 10;",

        "UPDATE users SET age = 20 WHERE id = 1;",

        """
        SELECT a.id
        FROM a
        JOIN b ON a.id = b.id;
        """,

        """
        SELECT a.id
        FROM a
        JOIN b USING (id);
        """,

        "-- DELETE FROM users;",

        ""
    ]
)
def test_safe_queries(source):

    assert analyze(source) == []


def test_duplicate_queries():

    source = """
SELECT name FROM users;
select name from users;
"""

    findings = analyze(source)

    duplicates = [
        finding for finding in findings
        if finding.rule_id == "SQL008"
    ]

    assert len(duplicates) == 1


def test_nested_subqueries():

    source = """
    SELECT id FROM a WHERE id IN (
        SELECT id FROM b WHERE id IN (
            SELECT id FROM c WHERE id IN (
                SELECT id FROM d
            )
        )
    );
    """

    findings = analyze(source)

    assert any(
        finding.rule_id == "SQL007"
        for finding in findings
    )


def test_line_numbers():

    source = (
        "SELECT name FROM users;\n"
        "\n"
        "DELETE FROM users;\n"
    )

    findings = analyze(source)

    assert findings[0].start_line == 3


def test_invalid_sql():

    findings = analyze(
        "SELECT ( FROM users;"
    )

    assert any(
        finding.rule_id == "SQL010"
        for finding in findings
    )


def test_semicolon_inside_string():

    source = """
SELECT 'hello;world';
DELETE FROM users WHERE id = 1;
"""

    assert analyze(source) == []


def test_dialect():

    analyzer = SQLAnalyzer(dialect="mysql")

    findings = analyzer.analyze(
        "SELECT `name` FROM `users`;",
        "test.sql"
    )

    assert findings == []