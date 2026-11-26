import math
from collections import Counter

from codesentry.core.models import (
    Token,
    Finding,
    Severity,
    HalsteadMetrics
)


class HalsteadAnalyzer:

    COMMON_OPERATORS = {
        "+", "-", "*", "/", "%", "=",
        "==", "!=", "<", ">", "<=", ">=",
        "+=", "-=", "*=", "/=", "%=",
        "&", "|", "^", "~", "<<", ">>",
        "&=", "|=", "^=", "<<=", ">>="
    }

    CPP_OPERATORS = COMMON_OPERATORS | {
        "++", "--", "&&", "||", "!",
        "?", "::", "->", ".", "new", "delete",
        "if", "else", "for", "while", "do",
        "switch", "case", "default",
        "return", "break", "continue",
        "throw", "try", "catch",
        "sizeof", "typedef", "using",
        "static_cast", "dynamic_cast",
        "reinterpret_cast", "const_cast",
        "and", "or", "not"
    }

    PYTHON_OPERATORS = COMMON_OPERATORS | {
        "**", "//", "**=", "//=",
        "and", "or", "not", "is", "in",
        "if", "elif", "else", "for", "while",
        "return", "break", "continue",
        "try", "except", "finally",
        "raise", "yield", "await",
        "import", "from", "as",
        "lambda", "with", "assert",
        "del", "match", "case",
        ":=", "@", "@=", "."
    }

    OPERAND_TYPES = {
        "identifier",
        "field_identifier",
        "type_identifier",
        "primitive_type",
        "number_literal",
        "integer",
        "float",
        "string",
        "string_literal",
        "string_content",
        "char_literal",
        "raw_string_literal",
        "true",
        "false",
        "none",
        "null",
        "nullptr"
    }

    def __init__(self, volume_threshold: float = 1000):

        if volume_threshold <= 0:
            raise ValueError("Threshold must be positive")

        self.volume_threshold = volume_threshold

    def calculate(
        self,
        tokens: list[Token],
        language: str
    ) -> HalsteadMetrics:

        operator_counts = Counter()
        operand_counts = Counter()

        if language == "cpp":
            operators = self.CPP_OPERATORS

        elif language == "python":
            operators = self.PYTHON_OPERATORS

        else:
            raise ValueError(
                f"Unsupported language: {language}"
            )

        for token in tokens:

            if token.type in self.OPERAND_TYPES:
                operand_counts[token.value] += 1

            elif token.value in operators:
                operator_counts[token.value] += 1

        n1 = len(operator_counts)
        n2 = len(operand_counts)

        N1 = sum(operator_counts.values())
        N2 = sum(operand_counts.values())

        vocabulary = n1 + n2
        length = N1 + N2

        volume = (
            length * math.log2(vocabulary)
            if vocabulary > 0
            else 0.0
        )

        difficulty = (
            (n1 / 2) * (N2 / n2)
            if n2 > 0
            else 0.0
        )

        effort = difficulty * volume

        return HalsteadMetrics(
            distinct_operators=n1,
            distinct_operands=n2,
            total_operators=N1,
            total_operands=N2,
            vocabulary=vocabulary,
            length=length,
            volume=round(volume, 2),
            difficulty=round(difficulty, 2),
            effort=round(effort, 2),
            estimated_time=round(effort / 18, 2),
            estimated_bugs=round(volume / 3000, 4)
        )

    def analyze(
        self,
        tokens: list[Token],
        language: str,
        file_path: str
    ):

        metrics = self.calculate(tokens, language)

        findings = []

        if tokens and metrics.volume > self.volume_threshold:

            findings.append(
                Finding(
                    rule_id="HAL001",
                    message=(
                        f"High Halstead volume: {metrics.volume}. "
                        f"Threshold: {self.volume_threshold}."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    start_line=tokens[0].line,
                    end_line=tokens[-1].line,
                    suggestion=(
                        "Reduce unnecessary complexity "
                        "and refactor large code blocks."
                    )
                )
            )

        return metrics, findings