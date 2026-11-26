from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Token:

    value: str
    type: str
    line: int
    column: int


@dataclass
class Finding:

    rule_id: str
    message: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    suggestion: str = ""


@dataclass
class AnalysisResult:

    file_path: str
    language: str

    findings: list[Finding] = field(
        default_factory=list
    )

    metrics: dict = field(default_factory=dict)


@dataclass
class DuplicateBlock:

    original_file: str
    original_start: int
    original_end: int

    duplicate_file: str
    duplicate_start: int
    duplicate_end: int

    token_count: int


@dataclass
class DuplicationResult:

    total_tokens: int = 0
    duplicated_tokens: int = 0

    blocks: list[DuplicateBlock] = field(
        default_factory=list
    )

    @property
    def duplication_percentage(self) -> float:

        if self.total_tokens == 0:
            return 0.0

        return round(
            self.duplicated_tokens
            / self.total_tokens * 100,
            2
        )


@dataclass
class FunctionComplexity:

    name: str
    start_line: int
    end_line: int
    complexity: int


@dataclass
class HalsteadMetrics:

    distinct_operators: int
    distinct_operands: int

    total_operators: int
    total_operands: int

    vocabulary: int
    length: int

    volume: float
    difficulty: float
    effort: float
    estimated_time: float
    estimated_bugs: float