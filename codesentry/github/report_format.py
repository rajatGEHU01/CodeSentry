

from urllib.parse import quote
import html
import re


ISSUE_TITLES = {
    "CPP001": "Unsafe input function",
    "CPP002": "Potential buffer overflow",
    "CPP003": "Unsafe string concatenation",
    "CPP004": "Unsafe formatted output",
    "CPP005": "Unsafe variadic formatting",
    "CPP006": "Potential command injection",
    "CPP007": "Unsafe shell process execution",
    "CPP008": "Insecure temporary filename",

    "SEC001": "Potential AWS credential",
    "SEC002": "Potential GitHub access token",
    "SEC003": "Potential fine-grained GitHub token",
    "SEC004": "Exposed private key",
    "SEC005": "Potential Google API key",
    "SEC006": "Potential Stripe credential",
    "SEC007": "Potential Slack token",
    "SEC008": "Database credentials in source",
    "SEC009": "Potential high-entropy secret",
    "SEC010": "Potential hardcoded credential",

    "PY001": "Unsafe eval execution",
    "PY002": "Unsafe exec execution",
    "PY003": "Unsafe deserialization",
    "PY004": "Potential command injection",
    "PY005": "Weak hash algorithm",
    "PY006": "Unsafe YAML loading",
    "PY007": "Shell execution enabled",
    "PY008": "TLS verification disabled",

    "SQL001": "DELETE without WHERE",
    "SQL002": "UPDATE without WHERE",
    "SQL003": "Wildcard SELECT",
    "SQL004": "Cartesian join",
    "SQL005": "Destructive DROP",
    "SQL006": "Destructive TRUNCATE",
    "SQL007": "Deeply nested subqueries",
    "SQL008": "Repeated SQL statement",
    "SQL009": "Always-true destructive condition",
    "SQL010": "SQL parsing error",

    "CYC001": "Excessive function complexity",
    "HAL001": "Excessive Halstead volume",
    "DUP001": "Potential duplicate code",

    "CFG001": "Unreachable code",
    "TAINT001": "Potential SQL injection",
    "TAINT002": "Potential command injection"
}


def issue_title(f):

    return ISSUE_TITLES.get(
        f.rule_id,
        "Code issue: " + f.rule_id
    )


def safe(value, limit=500):

    value = html.escape(
        str(value)[:limit],
        quote=False
    ).replace("@", "@\u200b")

    value = " ".join(value.splitlines())

    return re.sub(
        r"([\\`*_\[\]|~])",
        r"\\\1",
        value
    )


def category(f):

    if f.rule_id.startswith(
        ("SEC", "CPP", "PY", "TAINT")
    ):
        return "Security risks"

    if f.rule_id == "DUP001":
        return "Code duplication"

    if f.rule_id.startswith("SQL"):
        return "SQL issues"

    return "Code quality"


def location(analysis, f):

    event = analysis.event

    path = quote(f.file_path, safe="/")

    url = (
        f"https://github.com/"
        f"{quote(event.owner, safe='')}/"
        f"{quote(event.repository, safe='')}/"
        f"blob/{quote(event.head_sha, safe='')}/"
        f"{path}#L{f.start_line}"
    )

    return (
        f"[{safe(f.file_path, 180)}:"
        f"{f.start_line}]({url})"
    )
def severity_bar(count, total, width=20):

    if total == 0 or count == 0:
        filled = 0
    else:
        filled = max(1, round(count / total * width))

    filled = min(filled, width)

    return "█" * filled + "░" * (width - filled)


def severity_icon(severity):

    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪"
    }.get(severity, "⚪")


def render_summary(analysis):

    report = analysis.report
    status = analysis.gate.status.value

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    findings = sorted(
        analysis.findings,
        key=lambda f: (
            severity_order.get(f.severity.value, 99),
            f.file_path,
            f.start_line
        )
    )

    total = len(findings)

    counts = {
        severity: 0
        for severity in severity_order
    }

    for finding in findings:

        severity = finding.severity.value

        if severity in counts:
            counts[severity] += 1

    duplication = report.duplication.duplication_percentage

    # Collect function complexity metrics
    functions = []

    for result in report.files:

        for function in result.metrics.get("cyclomatic", []):

            functions.append({
                "name": function["name"],
                "complexity": function["complexity"],
                "file": result.file_path,
                "line": function["start_line"]
            })

    functions.sort(
        key=lambda f: f["complexity"],
        reverse=True
    )

    max_complexity = (
        functions[0]["complexity"]
        if functions else None
    )

    status_text = {
        "passed": "🟢 PASSED",
        "failed": "🔴 FAILED",
        "error": "⚠️ ANALYSIS INCOMPLETE"
    }.get(status, status.upper())

    # Main overview
    lines = [
        "# 🛡️ CodeSentry",
        "",
        "Automated Security & Code Quality Analysis",
        "",
        f"## Quality Gate: {status_text}",
        "",
        "| Analysis metric | Result |",
        "|---|---:|",
        f"| Files changed | {analysis.changed_files} |",
        f"| Files analyzed | {analysis.analyzed_files} |",
        f"| Total findings | **{total}** |",
        f"| Token duplication | **{duplication:.2f}%** |",
        (
            f"| Maximum complexity | "
            f"{max_complexity if max_complexity is not None else 'N/A'} |"
        ),
        f"| Analysis errors | {len(report.errors)} |",
        f"| Skipped files | {len(report.skipped_files)} |",
        f"| Analysis time | {report.duration_seconds:.3f}s |",
        "",
        "---",
        "",
        "## Severity Distribution",
        "",
        "| Severity | Distribution | Count |",
        "|---|---|---:|"
    ]

    # Severity visualization
    for severity, count in counts.items():

        bar = severity_bar(count, total)

        lines.append(
            f"| {severity_icon(severity)} "
            f"{severity.capitalize()} | "
            f"`{bar}` | **{count}** |"
        )

    lines += ["", "---", ""]

    # Quality gate evaluation
    lines += [
        "## Quality Gate Evaluation",
        ""
    ]

    if analysis.gate.violations:

        lines += [
            "| Status | Metric | Actual | Allowed |",
            "|---|---|---:|---:|"
        ]

        for violation in analysis.gate.violations[:20]:

            metric = violation.metric.replace(
                "_", " "
            ).title()

            unit = (
                "%"
                if violation.metric == "duplication"
                else ""
            )

            lines.append(
                f"| ❌ | {safe(metric)} | "
                f"**{safe(violation.actual)}{unit}** | "
                f"{safe(violation.allowed)}{unit} |"
            )

        lines += [
            "",
            "> The pull request does not satisfy "
            "the configured quality requirements.",
            ""
        ]

    elif status == "passed":

        lines += [
            "✅ All configured quality gate conditions passed.",
            ""
        ]

    else:

        lines += [
            "⚠️ Quality gate evaluation is incomplete.",
            ""
        ]

    # Categorize findings
    groups = {
        "Security risks": [],
        "SQL issues": [],
        "Code quality": [],
        "Code duplication": []
    }

    for finding in findings:

        groups[category(finding)].append(finding)

    lines += [
        "---",
        "",
        "## Issue Overview",
        "",
        "| Category | Findings |",
        "|---|---:|",
        f"| 🔐 Security risks | {len(groups['Security risks'])} |",
        f"| 🗄️ SQL issues | {len(groups['SQL issues'])} |",
        f"| ⚙️ Code quality | {len(groups['Code quality'])} |",
        f"| 📑 Code duplication | {len(groups['Code duplication'])} |",
        ""
    ]

    # Expandable findings
    lines += [
        "## Detailed Findings",
        ""
    ]

    if not findings:

        if report.errors or report.skipped_files:

            lines.append(
                "⚠️ No findings reported, but analysis "
                "coverage is incomplete."
            )

        elif analysis.analyzed_files == 0:

            lines.append("No eligible files were analyzed.")

        else:

            lines.append(
                "✅ No issues detected within the analyzed scope."
            )

        lines.append("")

    for group, items in groups.items():

        if not items:
            continue

        lines += [
            f"### {group} ({len(items)})",
            ""
        ]

        limit = 10

        for finding in items[:limit]:

            severity = finding.severity.value

            title = html.escape(
                issue_title(finding)
            )

            lines += [
                "<details>",
                (
                    f"<summary>"
                    f"{severity_icon(severity)} "
                    f"{severity.upper()} — "
                    f"{title} "
                    f"({html.escape(finding.rule_id)})"
                    f"</summary>"
                ),
                "",
                f"**Location:** {location(analysis, finding)}",
                "",
                f"**Rule:** `{safe(finding.rule_id)}`",
                "",
                f"**Problem:** {safe(finding.message)}",
                "",
                (
                    f"**How to fix:** "
                    f"{safe(finding.suggestion or 'Review the affected code.')}"
                ),
                "",
                "</details>",
                ""
            ]

        if len(items) > limit:

            lines += [
                f"Showing {limit} of {len(items)} findings.",
                ""
            ]

    # Function complexity visualization
    lines += [
        "---",
        "",
        "## Function Complexity",
        ""
    ]

    if functions:

        scale = max(
            1,
            max_complexity
        )

        lines += [
            "| Function | Complexity | Score |",
            "|---|---|---:|"
        ]

        for function in functions[:10]:

            score = function["complexity"]

            bar = severity_bar(
                score,
                scale,
                width=15
            )

            lines.append(
                f"| {safe(function['name'], 80)} "
                f"({safe(function['file'], 120)}:"
                f"{function['line']}) | "
                f"`{bar}` | **{score}** |"
            )

        lines += [
            "",
            "Higher cyclomatic complexity indicates "
            "more independent execution paths.",
            ""
        ]

    else:

        lines += [
            "No function complexity metrics available.",
            ""
        ]

    # Duplication overview
    lines += [
        "---",
        "",
        "## Code Duplication",
        "",
        f"**Detected token duplication: {duplication:.2f}%**",
        "",
        f"`{severity_bar(duplication, 100, 25)}`",
        "",
        f"Duplicate blocks: {len(report.duplication.blocks)}",
        ""
    ]

    # Analysis errors
    if report.errors:

        lines += [
            "## ⚠️ Analysis Errors",
            ""
        ]

        for error in report.errors[:10]:

            lines.append(
                f"- **{safe(error.file_path)}** — "
                f"{safe(error.stage)}: "
                f"{safe(error.message)}"
            )

        lines.append("")

    # Skipped files
    if report.skipped_files:

        lines += [
            "## Skipped Files",
            ""
        ]

        for path, reason in list(
            report.skipped_files.items()
        )[:10]:

            lines.append(
                f"- {safe(path)} — {safe(reason)}"
            )

        lines.append("")

    lines += [
        "---",
        "",
        "**Analysis Scope:** Python, C++ and SQL.",
        "",
        "Powered by rule-based static analysis, "
        "AST parsing and algorithmic code inspection.",
        "",
        "Findings represent potential issues "
        "and should be reviewed before merging."
    ]

    return "\n".join(lines)