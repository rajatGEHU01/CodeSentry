import ast
import re

from codesentry.core.models import Finding, Severity
from codesentry.parsers.ast_utils import (
    traverse_ast,
    get_node_text
)


class UnsafeFunctionAnalyzer:

    CPP_RULES = {
        "gets": (
            "CPP001",
            Severity.CRITICAL,
            "Unsafe input function may cause buffer overflow.",
            "Use fgets or std::getline."
        ),
        "strcpy": (
            "CPP002",
            Severity.HIGH,
            "Unbounded string copying may cause buffer overflow.",
            "Use std::string or a bounds-checked alternative."
        ),
        "strcat": (
            "CPP003",
            Severity.HIGH,
            "Unbounded string concatenation.",
            "Use std::string with appropriate size checks."
        ),
        "sprintf": (
            "CPP004",
            Severity.HIGH,
            "Unbounded formatted output.",
            "Use snprintf with the destination buffer size."
        ),
        "vsprintf": (
            "CPP005",
            Severity.HIGH,
            "Unbounded formatted output.",
            "Use vsnprintf with the destination buffer size."
        ),
        "system": (
            "CPP006",
            Severity.HIGH,
            "Shell command execution may allow command injection.",
            "Avoid shell execution and use structured process APIs."
        ),
        "popen": (
            "CPP007",
            Severity.HIGH,
            "Potentially unsafe shell command execution.",
            "Avoid passing untrusted input to shell commands."
        ),
        "tmpnam": (
            "CPP008",
            Severity.MEDIUM,
            "Temporary filename generation may introduce race conditions.",
            "Use a secure temporary file creation API."
        )
    }

    PYTHON_RULES = {
        "eval": (
            "PY001",
            Severity.HIGH,
            "Dynamic expression evaluation may execute arbitrary code.",
            "Avoid eval; use structured parsing."
        ),
        "exec": (
            "PY002",
            Severity.HIGH,
            "Dynamic code execution.",
            "Avoid executing dynamically constructed code."
        ),
        "pickle.load": (
            "PY003",
            Severity.HIGH,
            "Unsafe deserialization of potentially untrusted data.",
            "Use JSON or another safe serialization format."
        ),
        "pickle.loads": (
            "PY003",
            Severity.HIGH,
            "Unsafe deserialization of potentially untrusted data.",
            "Use JSON or another safe serialization format."
        ),
        "os.system": (
            "PY004",
            Severity.HIGH,
            "Shell execution may allow command injection.",
            "Use subprocess with an argument list and shell=False."
        ),
        "os.popen": (
            "PY004",
            Severity.HIGH,
            "Potentially unsafe shell execution.",
            "Use subprocess without shell execution."
        ),
        "hashlib.md5": (
            "PY005",
            Severity.LOW,
            "MD5 is unsuitable for security-sensitive hashing.",
            "Use SHA-256 or an appropriate password hashing algorithm."
        ),
        "hashlib.sha1": (
            "PY005",
            Severity.LOW,
            "SHA-1 is unsuitable for security-sensitive hashing.",
            "Use SHA-256 or an appropriate password hashing algorithm."
        ),
        "yaml.unsafe_load": (
            "PY006",
            Severity.HIGH,
            "Unsafe YAML deserialization.",
            "Use yaml.safe_load."
        )
    }

    SUBPROCESS_FUNCTIONS = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output"
    }

    HTTP_METHODS = {
        "get", "post", "put", "delete",
        "patch", "head", "request", "options"
    }

    @staticmethod
    def make_finding(rule, file_path, start, end):

        rule_id, severity, message, suggestion = rule

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            file_path=file_path,
            start_line=start,
            end_line=end,
            suggestion=suggestion
        )

    def analyze_cpp(self, root, source_code, file_path):

        findings = []
        source_bytes = source_code.encode("utf-8")

        for node in traverse_ast(root):

            if node.type != "call_expression":
                continue

            function = node.child_by_field_name("function")

            if function is None:
                continue

            name = get_node_text(function, source_bytes)
            name = re.sub(r"\s+", "", name)

            # Ignore object member calls.
            if "." in name or "->" in name:
                continue

            # Accept global and standard namespace calls.
            name = name.removeprefix("::")
            name = name.removeprefix("std::")

            rule = self.CPP_RULES.get(name)

            if rule is None:
                continue

            findings.append(
                self.make_finding(
                    rule,
                    file_path,
                    node.start_point.row + 1,
                    node.end_point.row + 1
                )
            )

        return findings

    @staticmethod
    def collect_imports(tree):

        aliases = {}

        for node in ast.walk(tree):

            if isinstance(node, ast.Import):

                for item in node.names:

                    if item.asname:
                        aliases[item.asname] = item.name
                    else:
                        root = item.name.split(".")[0]
                        aliases[root] = root

            elif isinstance(node, ast.ImportFrom):

                if node.level or not node.module:
                    continue

                for item in node.names:

                    if item.name == "*":
                        continue

                    aliases[item.asname or item.name] = (
                        f"{node.module}.{item.name}"
                    )

        return aliases

    @staticmethod
    def resolve_name(node, aliases):

        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):

            parent = UnsafeFunctionAnalyzer.resolve_name(
                node.value, aliases
            )

            if parent:
                return f"{parent}.{node.attr}"

        return ""

    @staticmethod
    def has_keyword_value(node, name, value):

        return any(
            keyword.arg == name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is value
            for keyword in node.keywords
        )

    def is_safe_yaml(self, node, aliases):

        loader = None

        for keyword in node.keywords:

            if keyword.arg == "Loader":
                loader = keyword.value
                break

        if loader is None and len(node.args) >= 2:
            loader = node.args[1]

        if loader is None:
            return False

        return self.resolve_name(loader, aliases) in {
            "yaml.SafeLoader",
            "yaml.CSafeLoader"
        }

    def analyze_python(self, source_code, file_path):

        try:
            tree = ast.parse(source_code)

        except SyntaxError:
            return []

        aliases = self.collect_imports(tree)
        findings = []

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            name = self.resolve_name(node.func, aliases)

            if name.startswith("builtins."):
                name = name.removeprefix("builtins.")

            rule = self.PYTHON_RULES.get(name)

            if name == "yaml.load":

                if not self.is_safe_yaml(node, aliases):

                    rule = (
                        "PY006",
                        Severity.HIGH,
                        "Potentially unsafe YAML loading.",
                        "Use yaml.safe_load or yaml.SafeLoader."
                    )

            elif name in self.SUBPROCESS_FUNCTIONS:

                if self.has_keyword_value(
                    node, "shell", True
                ):

                    rule = (
                        "PY007",
                        Severity.HIGH,
                        "Subprocess executes through a shell.",
                        "Use an argument list with shell=False."
                    )

            elif name.startswith("requests."):

                method = name.removeprefix("requests.")

                if (
                    method in self.HTTP_METHODS
                    and self.has_keyword_value(
                        node, "verify", False
                    )
                ):

                    rule = (
                        "PY008",
                        Severity.HIGH,
                        "SSL certificate verification is disabled.",
                        "Enable certificate verification."
                    )

            if rule is not None:

                findings.append(
                    self.make_finding(
                        rule,
                        file_path,
                        node.lineno,
                        node.end_lineno or node.lineno
                    )
                )

        return sorted(
            findings,
            key=lambda item: (
                item.start_line,
                item.rule_id
            )
        )

    def analyze(
        self,
        root,
        source_code,
        language,
        file_path
    ):

        if language == "cpp":

            return self.analyze_cpp(
                root, source_code, file_path
            )

        if language == "python":

            return self.analyze_python(
                source_code, file_path
            )

        return []