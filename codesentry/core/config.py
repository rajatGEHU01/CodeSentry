from dataclasses import dataclass, field


@dataclass(frozen=True)
class AnalysisConfig:

    min_duplicate_tokens: int = 20

    cyclomatic_threshold: int = 10
    halstead_volume_threshold: float = 1000

    entropy_threshold: float = 3.5
    min_entropy_length: int = 16

    sql_dialect: str | None = None
    max_subquery_depth: int = 2

    max_file_size: int = 1_000_000

    enable_duplication: bool = True
    enable_cyclomatic: bool = True
    enable_halstead: bool = True
    enable_secrets: bool = True
    enable_unsafe_functions: bool = True
    enable_sql: bool = True

    disabled_rules: frozenset[str] = field(
        default_factory=frozenset
    )

    def __post_init__(self):

        positive_values = {
            "min_duplicate_tokens": self.min_duplicate_tokens,
            "cyclomatic_threshold": self.cyclomatic_threshold,
            "halstead_volume_threshold": self.halstead_volume_threshold,
            "entropy_threshold": self.entropy_threshold,
            "min_entropy_length": self.min_entropy_length,
            "max_file_size": self.max_file_size
        }

        for name, value in positive_values.items():

            if value <= 0:
                raise ValueError(f"{name} must be positive")

        if self.max_subquery_depth < 0:
            raise ValueError(
                "max_subquery_depth cannot be negative"
            )