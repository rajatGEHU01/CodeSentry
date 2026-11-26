import pytest

from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.python_parser import PythonParser

from codesentry.analyzers.unsafe_functions import (
    UnsafeFunctionAnalyzer
)


def analyze(source, language):

    parser = (
        CppParser()
        if language == "cpp"
        else PythonParser()
    )

    tree = parser.parse(source)

    return UnsafeFunctionAnalyzer().analyze(
        tree.root_node,
        source,
        language,
        f"test.{language}"
    )


@pytest.mark.parametrize(
    "source,rule_id",
    [
        ("gets(buffer);", "CPP001"),
        ("strcpy(a, b);", "CPP002"),
        ("strcat(a, b);", "CPP003"),
        ("sprintf(a, b);", "CPP004"),
        ("vsprintf(a, b, c);", "CPP005"),
        ("system(cmd);", "CPP006"),
        ("popen(cmd, mode);", "CPP007"),
        ("tmpnam(buffer);", "CPP008"),
        ("std::strcpy(a, b);", "CPP002")
    ]
)
def test_cpp_unsafe(source, rule_id):

    source = "void test() { " + source + " }"

    findings = analyze(source, "cpp")

    assert any(
        item.rule_id == rule_id
        for item in findings
    )


@pytest.mark.parametrize(
    "source,rule_id",
    [
        ("eval(data)", "PY001"),
        ("exec(data)", "PY002"),
        ("pickle.loads(data)", "PY003"),
        ("os.system(cmd)", "PY004"),
        ("hashlib.md5(data)", "PY005"),
        ("yaml.load(data)", "PY006"),
        ("yaml.unsafe_load(data)", "PY006"),
        (
            "subprocess.run(cmd, shell=True)",
            "PY007"
        ),
        (
            "requests.get(url, verify=False)",
            "PY008"
        )
    ]
)
def test_python_unsafe(source, rule_id):

    findings = analyze(source, "python")

    assert any(
        item.rule_id == rule_id
        for item in findings
    )


@pytest.mark.parametrize(
    "source",
    [
        "yaml.safe_load(data)",
        "yaml.load(data, Loader=yaml.SafeLoader)",
        "yaml.load(data, yaml.SafeLoader)",
        "subprocess.run(cmd, shell=False)",
        "requests.get(url, verify=True)",
        "hashlib.sha256(data)",
        '# eval(data)',
        'message = "eval(data)"'
    ]
)
def test_safe_python(source):

    assert analyze(source, "python") == []


def test_import_alias():

    source = """
import os as operating_system
operating_system.system(cmd)
"""

    findings = analyze(source, "python")

    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"


def test_from_import_alias():

    source = """
from pickle import loads as deserialize
deserialize(data)
"""

    findings = analyze(source, "python")

    assert len(findings) == 1
    assert findings[0].rule_id == "PY003"


def test_cpp_comment():

    source = """
void test() {
    // strcpy(a, b);
}
"""

    assert analyze(source, "cpp") == []


def test_cpp_member_function():

    source = """
void test() {
    object.system();
}
"""

    assert analyze(source, "cpp") == []


def test_empty_source():

    assert analyze("", "python") == []