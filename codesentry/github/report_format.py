from urllib.parse import quote
import html
import re

ISSUE_TITLES = {
    "CPP001": "Unsafe input function", "CPP002": "Potential buffer overflow",
    "CPP003": "Unsafe string concatenation", "CPP004": "Unsafe formatted output",
    "CPP005": "Unsafe variadic formatting", "CPP006": "Potential command injection",
    "CPP007": "Unsafe shell process execution", "CPP008": "Insecure temporary filename",
    "SEC001": "Potential AWS credential", "SEC002": "Potential GitHub access token",
    "SEC003": "Potential fine-grained GitHub token", "SEC004": "Exposed private key",
    "SEC005": "Potential Google API key", "SEC006": "Potential Stripe credential",
    "SEC007": "Potential Slack token", "SEC008": "Database credentials in source",
    "SEC009": "Potential high-entropy secret", "SEC010": "Potential hardcoded credential",
    "PY001": "Unsafe eval execution", "PY002": "Unsafe exec execution",
    "PY003": "Unsafe deserialization", "PY004": "Potential command injection",
    "PY005": "Weak hash algorithm", "PY006": "Unsafe YAML loading",
    "PY007": "Shell execution enabled", "PY008": "TLS verification disabled",
    "SQL001": "DELETE without WHERE", "SQL002": "UPDATE without WHERE",
    "SQL003": "Wildcard SELECT", "SQL004": "Cartesian join", "SQL005": "Destructive DROP",
    "SQL006": "Destructive TRUNCATE", "SQL007": "Deeply nested subqueries",
    "SQL008": "Repeated SQL statement", "SQL009": "Always-true destructive condition",
    "SQL010": "SQL parsing error", "CYC001": "Excessive function complexity",
    "HAL001": "Excessive Halstead volume", "DUP001": "Potential duplicate code",
}

def issue_title(f):
    return ISSUE_TITLES.get(f.rule_id, "Code issue: " + f.rule_id)

def safe(value, limit=500):
    value = html.escape(str(value)[:limit], quote=False).replace("@", "@\u200b")
    value = " ".join(value.splitlines())
    return re.sub(r"([\\`*_\[\]|~])", r"\\\1", value)

def category(f):
    if f.rule_id.startswith(("SEC", "CPP", "PY")):
        return "Security risks"
    if f.rule_id == "DUP001":
        return "Code duplication"
    if f.rule_id.startswith("SQL"):
        return "SQL issues"
    return "Code quality"

def location(analysis, f):
    e = analysis.event
    path = quote(f.file_path, safe="/")
    url = f"https://github.com/{quote(e.owner, safe='')}/{quote(e.repository, safe='')}/blob/{quote(e.head_sha, safe='')}/{path}#L{f.start_line}"
    return f"[{safe(f.file_path, 180)}:{f.start_line}]({url})"

def render_summary(analysis):
    report = analysis.report
    status = analysis.gate.status.value
    findings = sorted(analysis.findings, key=lambda f: ({"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(f.severity.value,99), f.file_path, f.start_line))
    groups = {name: [] for name in ("Security risks", "SQL issues", "Code quality", "Code duplication")}
    for f in findings:
        groups[category(f)].append(f)
    lines = ["## CodeSentry — " + {"passed":"Passed", "failed":"Changes needed", "error":"Analysis incomplete"}.get(status,status), "", f"**{len(findings)} findings** · {analysis.analyzed_files}/{analysis.changed_files} files analyzed · {report.duration_seconds:.3f}s", "", f"**Security:** {len(groups['Security risks'])} · **SQL:** {len(groups['SQL issues'])} · **Quality:** {len(groups['Code quality'])} · **Duplicate findings:** {len(groups['Code duplication'])}", ""]
    if analysis.gate.violations:
        lines += ["### Why the quality gate failed", "", "| Metric | Actual | Allowed |", "|---|---:|---:|"]
        for v in analysis.gate.violations[:20]:
            lines.append(f"| {safe(v.metric)} | {safe(v.actual)} | {safe(v.allowed)} |")
        lines.append("")
    for name, items in groups.items():
        if not items:
            continue
        lines += [f"### {name} ({len(items)})", "", "| Severity | Issue | Location |", "|---|---|---|"]
        cap = 8 if name == "Code duplication" else 15
        for f in items[:cap]:
            lines.append(f"| {f.severity.value.upper()} | {safe(issue_title(f))} | {location(analysis,f)} |")
        if len(items)>cap:
            lines += ["", f"Showing {cap} of {len(items)} findings in this category."]
        lines.append("")
    if not findings:
        lines += ["No issues detected within the analyzed scope.", ""]
    lines += [f"**Potential token duplication:** {report.duplication.duplication_percentage}%", "", f"Analysis errors: {len(report.errors)} · Skipped files: {len(report.skipped_files)}", ""]
    for error in report.errors[:10]:
        lines.append(f"- Analysis error: {safe(error.file_path)} — {safe(error.stage)} — {safe(error.message)}")
    for path, reason in list(report.skipped_files.items())[:10]:
        lines.append(f"- Skipped: {safe(path)} — {safe(reason)}")
    lines += ["", "Findings are potential issues, not proof of exploitability. See inline annotations for explanations and fixes."]
    return "\n".join(lines)
