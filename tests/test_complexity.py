import pytest

from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.python_parser import PythonParser
from codesentry.parsers.tokenizer import tokenize

from codesentry.analyzers.cyclomatic import CyclomaticAnalyzer
from codesentry.analyzers.halstead import HalsteadAnalyzer


@pytest.mark.parametrize(
    "language,parser,source,expected",
    [
        (
            "cpp",
            CppParser(),
            "int add(int a, int b) { return a + b; }",
            1
        ),
        (
            "cpp",
            CppParser(),
            """
            int check(int a, int b) {
                if (a > 0 && b > 0)
                    return 1;
                return 0;
            }
            """,
            3
        ),
        (
            "python",
            PythonParser(),
            """
def check(a, b):
    if a > 0 and b > 0:
        return 1
    return 0
""",
            3
        )
    ]
)
def test_cyclomatic(language, parser, source, expected):

    tree = parser.parse(source)

    assert not tree.root_node.has_error

    metrics, findings = CyclomaticAnalyzer().analyze(
        tree.root_node,
        source,
        language,
        "test"
    )

    assert len(metrics) == 1
    assert metrics[0].complexity == expected


def test_complexity_threshold():

    source = """
def check(a):
    if a > 0:
        return 1
    return 0
"""

    tree = PythonParser().parse(source)

    metrics, findings = CyclomaticAnalyzer(
        threshold=1
    ).analyze(
        tree.root_node,
        source,
        "python",
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "CYC001"


def test_halstead():

    source = "a = b + c"

    tree = PythonParser().parse(source)

    tokens = tokenize(tree.root_node, source)

    metrics = HalsteadAnalyzer().calculate(
        tokens, "python"
    )

    assert metrics.distinct_operators == 2
    assert metrics.distinct_operands == 3
    assert metrics.length == 5
    assert metrics.vocabulary == 5
    assert metrics.volume > 0


def test_empty_halstead():

    metrics = HalsteadAnalyzer().calculate(
        [], "python"
    )

    assert metrics.volume == 0
    assert metrics.difficulty == 0
    assert metrics.effort == 0