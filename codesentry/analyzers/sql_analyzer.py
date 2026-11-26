from bisect import bisect_right

from sqlglot import exp, tokenize
from sqlglot.errors import SqlglotError

from codesentry.core.models import Finding, Severity
from codesentry.parsers.sql_parser import SQLParser


class SQLAnalyzer:

    def __init__(
        self,
        dialect: str | None = None,
        max_subquery_depth: int = 2
    ):

        if max_subquery_depth < 0:
            raise ValueError("Invalid subquery depth")

        self.dialect = dialect
        self.max_subquery_depth = max_subquery_depth
        self.parser = SQLParser()

    @staticmethod
    def make_finding(
        rule_id,
        message,
        severity,
        file_path,
        start_line,
        end_line,
        suggestion
    ):

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            suggestion=suggestion
        )

    def split_statements(self, source):

        tokens = tokenize(
            source,
            read=self.dialect
        )

        line_offsets = [-1]

        line_offsets.extend(
            index
            for index, char in enumerate(source)
            if char == "\n"
        )

        def line_at(offset):
            return bisect_right(line_offsets, offset - 1)

        statements = []
        current = []

        for token in tokens:

            if token.token_type.name == "SEMICOLON":

                if current:

                    start = current[0].start
                    end = current[-1].end

                    statements.append((
                        source[start:end + 1],
                        line_at(start),
                        line_at(end)
                    ))

                    current = []

            else:
                current.append(token)

        if current:

            start = current[0].start
            end = current[-1].end

            statements.append((
                source[start:end + 1],
                line_at(start),
                line_at(end)
            ))

        return statements

    @staticmethod
    def is_always_true(node):

        while isinstance(node, exp.Paren):
            node = node.this

        if isinstance(node, exp.Boolean):
            return node.this is True

        if isinstance(node, exp.EQ):

            left = node.this
            right = node.expression

            if (
                isinstance(left, exp.Literal)
                and isinstance(right, exp.Literal)
            ):
                return left == right

        if isinstance(node, exp.Or):

            return (
                SQLAnalyzer.is_always_true(node.this)
                or SQLAnalyzer.is_always_true(node.expression)
            )

        if isinstance(node, exp.And):

            return (
                SQLAnalyzer.is_always_true(node.this)
                and SQLAnalyzer.is_always_true(node.expression)
            )

        return False

    @staticmethod
    def subquery_depth(root):

        maximum = 0
        stack = [(root, 0)]

        while stack:

            node, depth = stack.pop()

            if isinstance(node, exp.Subquery):
                depth += 1

            maximum = max(maximum, depth)

            for child in node.iter_expressions():
                stack.append((child, depth))

        return maximum

    def analyze_statement(
        self,
        statement,
        file_path,
        start_line,
        end_line
    ):

        findings = []

        def report(rule_id, message, severity, suggestion):

            findings.append(
                self.make_finding(
                    rule_id,
                    message,
                    severity,
                    file_path,
                    start_line,
                    end_line,
                    suggestion
                )
            )

        # Destructive queries
        for node in statement.walk():

            if isinstance(node, exp.Delete):

                if node.args.get("where") is None:

                    report(
                        "SQL001",
                        "DELETE without WHERE may remove all rows.",
                        Severity.HIGH,
                        "Add an appropriate WHERE condition."
                    )

            elif isinstance(node, exp.Update):

                if node.args.get("where") is None:

                    report(
                        "SQL002",
                        "UPDATE without WHERE may modify all rows.",
                        Severity.HIGH,
                        "Restrict the update using WHERE."
                    )

            elif isinstance(node, exp.Drop):

                report(
                    "SQL005",
                    "Potentially destructive DROP operation.",
                    Severity.HIGH,
                    "Review dependencies and migration safety."
                )

            elif isinstance(node, exp.TruncateTable):

                report(
                    "SQL006",
                    "TRUNCATE removes all rows from a table.",
                    Severity.HIGH,
                    "Confirm that complete data removal is intended."
                )

            # Always-true WHERE conditions
            if isinstance(node, (exp.Delete, exp.Update)):

                where = node.args.get("where")

                if (
                    where is not None
                    and self.is_always_true(where.this)
                ):

                    report(
                        "SQL009",
                        "Destructive query has an always-true WHERE condition.",
                        Severity.HIGH,
                        "Use a restrictive WHERE condition."
                    )

            # Wildcard projections
            if isinstance(node, exp.Select):

                for projection in node.expressions:

                    if (
                        isinstance(projection, exp.Star)
                        or (
                            isinstance(projection, exp.Column)
                            and isinstance(projection.this, exp.Star)
                        )
                    ):

                        report(
                            "SQL003",
                            "Wildcard column selection detected.",
                            Severity.LOW,
                            "Select only the required columns."
                        )

                        break

            # Cartesian joins
            if isinstance(node, exp.Join):

                kind = str(
                    node.args.get("kind") or ""
                ).upper()

                method = str(
                    node.args.get("method") or ""
                ).upper()

                has_condition = (
                    node.args.get("on") is not None
                    or bool(node.args.get("using"))
                )

                if (
                    kind == "CROSS"
                    or (
                        not has_condition
                        and method not in {"NATURAL", "POSITIONAL"}
                        and kind not in {"SEMI", "ANTI"}
                    )
                ):

                    report(
                        "SQL004",
                        "Potential Cartesian product detected.",
                        Severity.MEDIUM,
                        "Review join conditions and expected result size."
                    )

        depth = self.subquery_depth(statement)

        if depth > self.max_subquery_depth:

            report(
                "SQL007",
                f"Excessive subquery nesting: depth {depth}.",
                Severity.MEDIUM,
                "Review whether joins or CTEs simplify the query."
            )

        return findings

    def analyze(
        self,
        source_code: str,
        file_path: str
    ) -> list[Finding]:

        findings = []
        seen_statements = {}

        try:

            statements = self.split_statements(source_code)

        except SqlglotError:

            return [
                self.make_finding(
                    "SQL010",
                    "Unable to tokenize SQL source.",
                    Severity.MEDIUM,
                    file_path,
                    1,
                    max(1, len(source_code.splitlines())),
                    "Check SQL syntax and configured dialect."
                )
            ]

        for source, start_line, end_line in statements:

            try:

                parsed = self.parser.parse(
                    source,
                    dialect=self.dialect
                )

            except SqlglotError:

                findings.append(
                    self.make_finding(
                        "SQL010",
                        "Unable to parse SQL statement.",
                        Severity.MEDIUM,
                        file_path,
                        start_line,
                        end_line,
                        "Check SQL syntax and configured dialect."
                    )
                )

                continue

            for statement in parsed:

                if statement is None:
                    continue

                findings.extend(
                    self.analyze_statement(
                        statement,
                        file_path,
                        start_line,
                        end_line
                    )
                )

                # Canonical SQL for duplicate detection
                fingerprint = statement.sql(
                    dialect=self.dialect,
                    normalize=True,
                    comments=False
                )

                if fingerprint in seen_statements:

                    original_line = seen_statements[fingerprint]

                    findings.append(
                        self.make_finding(
                            "SQL008",
                            f"Repeated SQL statement from line {original_line}.",
                            Severity.MEDIUM,
                            file_path,
                            start_line,
                            end_line,
                            "Review whether repeated execution is necessary."
                        )
                    )

                else:
                    seen_statements[fingerprint] = start_line

        return findings