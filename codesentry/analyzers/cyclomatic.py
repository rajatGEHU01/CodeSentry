from codesentry.core.models import (
    Finding,
    Severity,
    FunctionComplexity
)

from codesentry.parsers.ast_utils import (
    traverse_ast,
    get_node_text
)


class CyclomaticAnalyzer:

    FUNCTION_TYPES = {
        "cpp": {"function_definition", "lambda_expression"},
        "python": {"function_definition", "lambda"}
    }

    DECISION_TYPES = {
        "cpp": {
            "if_statement",
            "for_statement",
            "for_range_loop",
            "while_statement",
            "do_statement",
            "conditional_expression",
            "catch_clause"
        },

        "python": {
            "if_statement",
            "elif_clause",
            "for_statement",
            "while_statement",
            "except_clause",
            "conditional_expression",
            "for_in_clause",
            "if_clause"
        }
    }

    LOGICAL_OPERATORS = {
        "cpp": {"&&", "||", "and", "or"},
        "python": {"and", "or"}
    }

    def __init__(self, threshold: int = 10):

        if threshold < 1:
            raise ValueError("Threshold must be positive")

        self.threshold = threshold

    def get_function_name(
        self, node, source_bytes, language
    ):

        if node.type in {"lambda", "lambda_expression"}:
            return "<lambda>"

        if language == "python":

            name = node.child_by_field_name("name")

            if name:
                return get_node_text(name, source_bytes)

        elif language == "cpp":

            current = node.child_by_field_name(
                "declarator"
            )

            while current is not None:

                if current.type in {
                    "identifier",
                    "field_identifier",
                    "qualified_identifier",
                    "operator_name",
                    "destructor_name"
                }:
                    return get_node_text(
                        current, source_bytes
                    )

                current = current.child_by_field_name(
                    "declarator"
                )

        return "<anonymous>"

    def calculate(self, function_node, language):

        complexity = 1

        decisions = self.DECISION_TYPES[language]
        operators = self.LOGICAL_OPERATORS[language]
        functions = self.FUNCTION_TYPES[language]

        body = function_node.child_by_field_name("body")

        if body is None:
            return complexity

        stack = [body]

        while stack:

            node = stack.pop()

            # Nested functions are analyzed separately
            if node.type in functions:
                continue

            if node.type in decisions:
                complexity += 1

            elif (
                language == "cpp"
                and node.type == "case_statement"
            ):
                # Exclude default cases
                if any(
                    child.type == "case"
                    for child in node.children
                ):
                    complexity += 1

            elif (
                language == "python"
                and node.type == "case_clause"
            ):
                # Count non-default match cases
                pattern = next(
                    (
                        child for child in node.named_children
                        if child.type == "case_pattern"
                    ),
                    None
                )

                if pattern is None or pattern.text != b"_":
                    complexity += 1

            elif node.type in {
                "binary_expression",
                "boolean_operator"
            }:

                operator = node.child_by_field_name(
                    "operator"
                )

                if operator and operator.type in operators:
                    complexity += 1

            stack.extend(reversed(node.children))

        return complexity

    def analyze(
        self,
        root,
        source_code: str,
        language: str,
        file_path: str
    ):

        if language not in self.FUNCTION_TYPES:
            return [], []

        source_bytes = source_code.encode("utf-8")

        metrics = []
        findings = []

        for node in traverse_ast(root):

            if node.type not in self.FUNCTION_TYPES[language]:
                continue

            name = self.get_function_name(
                node, source_bytes, language
            )

            complexity = self.calculate(node, language)

            start_line = node.start_point.row + 1
            end_line = node.end_point.row + 1

            metrics.append(
                FunctionComplexity(
                    name=name,
                    start_line=start_line,
                    end_line=end_line,
                    complexity=complexity
                )
            )

            if complexity > self.threshold:

                severity = (
                    Severity.HIGH
                    if complexity > self.threshold * 2
                    else Severity.MEDIUM
                )

                findings.append(
                    Finding(
                        rule_id="CYC001",
                        message=(
                            f"Function '{name}' has cyclomatic "
                            f"complexity {complexity}. "
                            f"Threshold: {self.threshold}."
                        ),
                        severity=severity,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        suggestion=(
                            "Split complex logic into smaller "
                            "functions and simplify conditions."
                        )
                    )
                )

        return metrics, findings