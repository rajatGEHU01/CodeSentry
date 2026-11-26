from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.python_parser import PythonParser
from codesentry.parsers.sql_parser import SQLParser


cpp_code = """
int add(int a, int b) {
    return a + b;
}
"""

python_code = """
def add(a, b):
    return a + b
"""

sql_code = """
SELECT name, salary
FROM employees
WHERE salary > 50000;
"""


cpp_tree = CppParser().parse(cpp_code)
python_tree = PythonParser().parse(python_code)
sql_trees = SQLParser().parse(sql_code)


print("C++ Syntax Tree:")
print(cpp_tree.root_node)

print("\nPython Syntax Tree:")
print(python_tree.root_node)

print("\nSQL Syntax Tree:")

for tree in sql_trees:
    print(repr(tree))