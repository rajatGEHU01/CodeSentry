import json
from pathlib import Path

from codesentry.core.report import RepositoryReport
from codesentry.core.quality_gate import QualityGateResult


class JSONReporter:

    @staticmethod
    def generate(
        report: RepositoryReport,
        gate: QualityGateResult | None = None
    ) -> str:

        data = report.to_dict()

        if gate is not None:

            data["quality_gate"] = gate.to_dict()

        return json.dumps(
            data,
            indent=4,
            ensure_ascii=False
        )

    @classmethod
    def save(
        cls,
        report: RepositoryReport,
        output_path: str,
        gate: QualityGateResult | None = None
    ) -> Path:

        path = Path(output_path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        path.write_text(
            cls.generate(report, gate),
            encoding="utf-8"
        )

        return path