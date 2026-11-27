import json

from pathlib import Path
from dataclasses import fields

from codesentry.core.config import AnalysisConfig
from codesentry.core.quality_gate import QualityGateConfig


def validate_keys(data, config_class):

    allowed = {
        item.name
        for item in fields(config_class)
    }

    unknown = set(data) - allowed

    if unknown:

        raise ValueError(
            f"Unknown configuration options: "
            f"{', '.join(sorted(unknown))}"
        )


def load_config(
    config_path: str = ".codesentry.json"
) -> tuple[AnalysisConfig, QualityGateConfig]:

    path = Path(config_path)

    if not path.exists():

        if config_path == ".codesentry.json":

            return AnalysisConfig(), QualityGateConfig()

        raise FileNotFoundError(config_path)

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("Configuration must be an object")

    unknown = set(data) - {"analysis", "quality_gate"}

    if unknown:
        raise ValueError("Unknown configuration section")

    analysis_data = data.get("analysis", {})
    gate_data = data.get("quality_gate", {})

    if not isinstance(analysis_data, dict):
        raise ValueError("Invalid analysis configuration")

    if not isinstance(gate_data, dict):
        raise ValueError("Invalid quality gate configuration")

    validate_keys(analysis_data, AnalysisConfig)
    validate_keys(gate_data, QualityGateConfig)

    if "disabled_rules" in analysis_data:

        rules = analysis_data["disabled_rules"]

        if not isinstance(rules, list) or not all(
            isinstance(rule, str)
            for rule in rules
        ):

            raise ValueError(
                "disabled_rules must be a list of strings"
            )

        analysis_data["disabled_rules"] = frozenset(rules)

    return (
        AnalysisConfig(**analysis_data),
        QualityGateConfig(**gate_data)
    )