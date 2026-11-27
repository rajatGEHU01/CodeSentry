import json

from codesentry.core.engine import AnalysisEngine
from codesentry.core.config import AnalysisConfig
from codesentry.reports.json_report import JSONReporter


def test_empty_repository():

    report = AnalysisEngine().analyze_repository({})

    assert report.files == []
    assert report.findings == []
    assert report.errors == []


def test_python_analysis():

    report = AnalysisEngine().analyze_repository({
        "test.py": "eval(data)"
    })

    assert len(report.files) == 1

    assert any(
        item.rule_id == "PY001"
        for item in report.findings
    )


def test_sql_analysis():

    report = AnalysisEngine().analyze_repository({
        "test.sql": "DELETE FROM users;"
    })

    assert any(
        item.rule_id == "SQL001"
        for item in report.findings
    )


def test_disabled_rule():

    config = AnalysisConfig(
        disabled_rules=frozenset({"PY001"})
    )

    report = AnalysisEngine(config).analyze_repository({
        "test.py": "eval(data)"
    })

    assert not any(
        item.rule_id == "PY001"
        for item in report.findings
    )


def test_disabled_analyzer():

    config = AnalysisConfig(
        enable_unsafe_functions=False
    )

    report = AnalysisEngine(config).analyze_repository({
        "test.py": "eval(data)"
    })

    assert report.findings == []


def test_large_file():

    config = AnalysisConfig(max_file_size=10)

    report = AnalysisEngine(config).analyze_repository({
        "large.py": "a" * 100
    })

    assert "large.py" in report.skipped_files
    assert report.files == []


def test_binary_file():

    report = AnalysisEngine().analyze_repository({
        "binary.txt": "abc\x00def"
    })

    assert "binary.txt" in report.skipped_files


def test_invalid_syntax():

    report = AnalysisEngine().analyze_repository({
        "invalid.py": "def broken("
    })

    assert len(report.errors) > 0

    assert any(
        error.stage == "parser"
        and "line" in error.message
        for error in report.errors
    )


def test_json_report():

    report = AnalysisEngine().analyze_repository({
        "test.py": "eval(data)"
    })

    data = json.loads(
        JSONReporter.generate(report)
    )

    assert data["summary"]["files_analyzed"] == 1
    assert data["summary"]["total_findings"] >= 1


def test_repository_duplication():

    source = """
int sum(int a, int b) {
    int result = a + b;
    return result;
}
"""

    config = AnalysisConfig(
        min_duplicate_tokens=20,
        min_duplicate_lines=1
    )

    report = AnalysisEngine(config).analyze_repository({
        "first.cpp": source,
        "second.cpp": source
    })

    assert report.duplication.duplication_percentage == 100.0

    assert any(
        item.rule_id == "DUP001"
        for item in report.findings
    )


def test_flow_integration():

    source = """
def calculate():
    return 10
    print(20)
"""

    report = AnalysisEngine().analyze_repository({
        "test.py": source
    })

    assert report.errors == []

    assert any(
        item.rule_id == "CFG001"
        for item in report.findings
    )

    assert "control_flow" in report.files[0].metrics


def test_sql_injection_integration():

    source = """
username = input()
query = "SELECT * FROM users WHERE name = " + username
cursor.execute(query)
"""

    report = AnalysisEngine().analyze_repository({
        "test.py": source
    })

    assert report.errors == []

    assert any(
        item.rule_id == "TAINT001"
        for item in report.findings
    )


def test_command_injection_integration():

    source = """
import os

command = input()
os.system(command)
"""

    report = AnalysisEngine().analyze_repository({
        "test.py": source
    })

    assert report.errors == []

    assert any(
        item.rule_id == "TAINT002"
        for item in report.findings
    )


def test_disabled_flow():

    config = AnalysisConfig(
        enable_flow=False
    )

    source = """
def calculate():
    return 10
    print(20)
"""

    report = AnalysisEngine(config).analyze_repository({
        "test.py": source
    })

    assert not any(
        item.rule_id == "CFG001"
        for item in report.findings
    )

    assert "control_flow" not in report.files[0].metrics


def test_safe_parameterized_query():

    source = """
username = input()
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (username,)
)
"""

    report = AnalysisEngine().analyze_repository({
        "test.py": source
    })

    assert report.errors == []

    assert not any(
        item.rule_id == "TAINT001"
        for item in report.findings
    )