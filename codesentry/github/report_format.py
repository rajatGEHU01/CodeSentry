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

    groups = {
        "Security risks": [],
        "SQL issues": [],
        "Code quality": [],
        "Code duplication": []
    }

    for finding in findings:

        groups[category(finding)].append(finding)

    status_titles = {
        "passed": "Passed",
        "failed": "Changes needed",
        "error": "Analysis incomplete"
    }

    lines = [
        "## CodeSentry — " + status_titles.get(
            status, status
        ),

        "",

        (
            f"**{len(findings)} finding(s)** · "
            f"{analysis.analyzed_files}/"
            f"{analysis.changed_files} files fully analyzed · "
            f"{report.duration_seconds:.3f}s"
        ),

        "",

        (
            f"**Security:** {len(groups['Security risks'])} · "
            f"**SQL:** {len(groups['SQL issues'])} · "
            f"**Quality:** {len(groups['Code quality'])} · "
            f"**Duplicate findings:** "
            f"{len(groups['Code duplication'])}"
        ),

        ""
    ]

    # Quality gate violations
    if analysis.gate.violations:

        lines += [
            "### Why the quality gate failed",
            "",
            "| Metric | Actual | Allowed |",
            "|---|---:|---:|"
        ]

        for violation in analysis.gate.violations[:20]:

            label = violation.metric.replace(
                "_", " "
            ).capitalize()

            unit = (
                "%"
                if violation.metric == "duplication"
                else ""
            )

            lines.append(
                f"| {safe(label)} | "
                f"{safe(violation.actual)}{unit} | "
                f"{safe(violation.allowed)}{unit} |"
            )

        lines.append("")

    # Group findings by category
    for name, items in groups.items():

        if not items:
            continue

        lines += [
            f"### {name} ({len(items)})",
            "",
            "| Severity | Issue | Location |",
            "|---|---|---|"
        ]

        cap = 8 if name == "Code duplication" else 15

        for finding in items[:cap]:

            lines.append(
                f"| {finding.severity.value.upper()} | "
                f"{safe(issue_title(finding))} | "
                f"{location(analysis, finding)} |"
            )

        if len(items) > cap:

            lines += [
                "",
                f"Showing {cap} of {len(items)} "
                f"findings in this category."
            ]

        lines.append("")

    # Never report clean results when analysis is incomplete
    if not findings:

        if report.errors or report.skipped_files:

            lines += [
                "**Analysis coverage is incomplete.**",
                "",
                "No findings were reported, but some "
                "analysis could not be completed.",
                ""
            ]

        elif analysis.analyzed_files == 0:

            lines += [
                "No eligible files were analyzed.",
                ""
            ]

        else:

            lines += [
                "No issues detected within the analyzed scope.",
                ""
            ]

    lines += [
        (
            "**Potential token duplication:** "
            f"{report.duplication.duplication_percentage}%"
        ),

        "",

        (
            f"Analysis errors: {len(report.errors)} · "
            f"Skipped files: {len(report.skipped_files)}"
        ),

        ""
    ]

    # Analysis errors
    for error in report.errors[:10]:

        lines.append(
            f"- Analysis error: {safe(error.file_path)} — "
            f"{safe(error.stage)} — "
            f"{safe(error.message)}"
        )

    # Skipped files
    for path, reason in list(
        report.skipped_files.items()
    )[:10]:

        lines.append(
            f"- Skipped: {safe(path)} — {safe(reason)}"
        )

    lines += [
        "",
        "Findings are potential issues, not proof of "
        "exploitability. See inline annotations "
        "for explanations and fixes."
    ]

    return "\n".join(lines)