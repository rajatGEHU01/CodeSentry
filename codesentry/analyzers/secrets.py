import math
import re
from collections import Counter

from codesentry.core.models import Finding, Severity


class SecretDetector:

    PATTERNS = {
        "SEC001": (
            "Potential AWS access key",
            re.compile(
                r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
            ),
            Severity.HIGH
        ),

        "SEC002": (
            "Potential GitHub access token",
            re.compile(
                r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)"
                r"[A-Za-z0-9]{36,255}\b"
            ),
            Severity.CRITICAL
        ),

        "SEC003": (
            "Potential GitHub fine-grained token",
            re.compile(
                r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"
            ),
            Severity.CRITICAL
        ),

        "SEC004": (
            "Hardcoded private key",
            re.compile(
                r"-----BEGIN "
                r"(?:[A-Z0-9]+ )*PRIVATE KEY-----"
            ),
            Severity.CRITICAL
        ),

        "SEC005": (
            "Potential Google API key",
            re.compile(
                r"\bAIza[A-Za-z0-9_-]{35}\b"
            ),
            Severity.HIGH
        ),

        "SEC006": (
            "Potential Stripe secret key",
            re.compile(
                r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b"
            ),
            Severity.HIGH
        ),

        "SEC007": (
            "Potential Slack token",
            re.compile(
                r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"
            ),
            Severity.HIGH
        ),

        "SEC008": (
            "Potential database credentials in URL",
            re.compile(
                r"\b(?:postgres(?:ql)?|mysql|mongodb"
                r"(?:\+srv)?|redis)://"
                r"[^:\s/]+:[^@\s/]+@"
            ),
            Severity.HIGH
        )
    }

    ASSIGNMENT_PATTERN = re.compile(
        r"""(?ix)
        \b
        (?P<name>
            [a-z_][a-z0-9_]*
        )
        ["']?
        \s*
        (?::\s*[\w.\[\]]+\s*)?
        (?:=|:)
        \s*
        (?P<quote>["'])
        (?P<value>[^"'\r\n]{1,1024})
        (?P=quote)
        """
    )

    SENSITIVE_NAME = re.compile(
        r"password|passwd|pwd|secret|token|"
        r"api_?key|access_?key|private_?key|"
        r"credential|client_?secret",
        re.IGNORECASE
    )

    PLACEHOLDERS = {
        "",
        "none",
        "null",
        "password",
        "changeme",
        "placeholder",
        "your_api_key",
        "your_token",
        "your_password",
        "your_secret",
        "example",
        "dummy",
        "redacted",
        "replace_me"
    }

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        min_entropy_length: int = 16
    ):

        if entropy_threshold <= 0:
            raise ValueError("Invalid entropy threshold")

        if min_entropy_length < 1:
            raise ValueError("Invalid minimum length")

        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length

    @staticmethod
    def shannon_entropy(value: str) -> float:

        if not value:
            return 0.0

        counts = Counter(value)
        length = len(value)

        return -sum(
            (count / length)
            * math.log2(count / length)
            for count in counts.values()
        )

    def is_placeholder(self, value: str) -> bool:

        normalized = value.strip().lower()

        if normalized in self.PLACEHOLDERS:
            return True

        if normalized.startswith((
            "your_",
            "replace_with_",
            "${",
            "{{",
            "<"
        )):
            return True

        if normalized and set(normalized) <= {"*"}:
            return True

        return False

    def analyze(
        self,
        source_code: str,
        file_path: str
    ) -> list[Finding]:

        findings = []

        for line_number, line in enumerate(
            source_code.splitlines(), start=1
        ):

            matched_spans = []

            # Provider-specific credential detection
            for rule_id, pattern_data in self.PATTERNS.items():

                message, pattern, severity = pattern_data

                for match in pattern.finditer(line):

                    matched_spans.append(match.span())

                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            message=message,
                            severity=severity,
                            file_path=file_path,
                            start_line=line_number,
                            end_line=line_number,
                            suggestion=(
                                "Remove the credential from "
                                "source code, revoke or rotate "
                                "it, and use a secret manager "
                                "or environment variable."
                            )
                        )
                    )

            # Context-based credential detection
            for match in self.ASSIGNMENT_PATTERN.finditer(line):

                name = match.group("name")
                value = match.group("value")

                if not self.SENSITIVE_NAME.search(name):
                    continue

                if self.is_placeholder(value):
                    continue

                start, end = match.span("value")

                # Avoid duplicate findings
                if any(
                    start < previous_end
                    and end > previous_start
                    for previous_start, previous_end
                    in matched_spans
                ):
                    continue

                entropy = self.shannon_entropy(value)

                high_entropy = (
                    len(value) >= self.min_entropy_length
                    and entropy >= self.entropy_threshold
                )

                if high_entropy:

                    rule_id = "SEC009"
                    severity = Severity.HIGH

                    message = (
                        "Potential hardcoded high-entropy "
                        f"credential (entropy: {entropy:.2f})."
                    )

                else:

                    rule_id = "SEC010"
                    severity = Severity.MEDIUM

                    message = (
                        "Potential hardcoded password "
                        "or credential."
                    )

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        message=message,
                        severity=severity,
                        file_path=file_path,
                        start_line=line_number,
                        end_line=line_number,
                        suggestion=(
                            "Store credentials outside source "
                            "code using environment variables "
                            "or a secret manager."
                        )
                    )
                )

        return findings