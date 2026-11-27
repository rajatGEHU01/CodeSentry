from codesentry.analyzers.flow import FlowAnalyzer


def rules(source):

    metrics, findings = FlowAnalyzer().analyze(
        source,
        "test.py"
    )

    return {finding.rule_id for finding in findings}


def test_sql_input():

    source = """
x = input()
cursor.execute("SELECT " + x)
"""

    assert "TAINT001" in rules(source)


def test_bound_parameter():

    source = """
x = input()
cursor.execute("SELECT ?", (x,))
"""

    assert "TAINT001" not in rules(source)


def test_shell():

    source = """
import os

x = input()
os.system(x)
"""

    assert "TAINT002" in rules(source)


def test_unreachable():

    source = """
def calculate():
    return 1
    print(2)
"""

    assert "CFG001" in rules(source)


def test_branch_merge():

    source = """
if flag:
    x = input()
else:
    x = "ok"

cursor.execute(x)
"""

    assert "TAINT001" in rules(source)


def test_overwrite():

    source = """
x = input()
x = "safe"

cursor.execute(x)
"""

    assert "TAINT001" not in rules(source)


def test_taint_propagation():

    source = """
username = input()
value = username
query = "SELECT " + value

cursor.execute(query)
"""

    assert "TAINT001" in rules(source)


def test_subprocess_shell():

    source = """
import subprocess

command = input()

subprocess.run(command, shell=True)
"""

    assert "TAINT002" in rules(source)


def test_reachable_code():

    source = """
def calculate(flag):
    if flag:
        return 1

    print(2)
"""

    assert "CFG001" not in rules(source)


def test_all_branches_return():

    source = """
def calculate(flag):
    if flag:
        return 1
    else:
        return 2

    print(3)
"""

    assert "CFG001" in rules(source)


def test_control_flow_edges():

    source = """
x = 10
y = 20
z = x + y
"""

    metrics, findings = FlowAnalyzer().analyze(
        source,
        "test.py"
    )

    assert metrics["edge_count"] == 2

    assert findings == []