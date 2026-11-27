import ast

from codesentry.core.models import Finding, Severity


class FlowAnalyzer:

    def analyze(self, source, path):

        tree = ast.parse(source)

        findings = []
        edges = set()
        seen = set()

        def emit(rule, node, message, severity, suggestion):

            key = (rule, node.lineno)

            if key not in seen:

                seen.add(key)

                findings.append(
                    Finding(
                        rule_id=rule,
                        message=message,
                        severity=severity,
                        file_path=path,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        suggestion=suggestion
                    )
                )

        def name(node):

            if isinstance(node, ast.Name):
                return node.id

            if isinstance(node, ast.Attribute):
                return name(node.value) + "." + node.attr

            return ""

        # Track untrusted input and its propagation.
        def tainted(node, env):

            if node is None:
                return False

            if isinstance(node, ast.Name):
                return node.id in env

            if isinstance(node, ast.Call):

                n = name(node.func)

                sources = {
                    "input",
                    "builtins.input",
                    "request.args.get",
                    "request.form.get",
                    "request.get_json"
                }

                if n in sources:
                    return True

                numeric_conversions = {
                    "int",
                    "float",
                    "builtins.int",
                    "builtins.float"
                }

                if n in numeric_conversions:
                    return False

                return (
                    any(
                        tainted(x, env)
                        for x in node.args
                    )
                    or any(
                        tainted(x.value, env)
                        for x in node.keywords
                    )
                    or (
                        isinstance(node.func, ast.Attribute)
                        and tainted(node.func.value, env)
                    )
                )

            if name(node) in {
                "request.args",
                "request.form",
                "request.values",
                "request.json",
                "sys.argv"
            }:
                return True

            return any(
                tainted(x, env)
                for x in ast.iter_child_nodes(node)
            )

        # Identify dangerous sinks.
        def inspect(node, env):

            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda
                )
            ):
                return

            if (
                isinstance(node, ast.Call)
                and node.args
                and tainted(node.args[0], env)
            ):

                n = name(node.func)

                # SQL injection detection.
                if n.endswith(
                    (
                        ".execute",
                        ".executemany",
                        ".executescript"
                    )
                ):

                    emit(
                        "TAINT001",
                        node,
                        "Potential untrusted input reaches SQL query text.",
                        Severity.HIGH,
                        "Use parameterized queries and bind values separately."
                    )

                # Detect shell=True.
                shell = any(
                    k.arg == "shell"
                    and isinstance(k.value, ast.Constant)
                    and k.value.value is True
                    for k in node.keywords
                )

                # Command injection detection.
                if (
                    n in {"os.system", "os.popen"}
                    or (
                        n.startswith("subprocess.")
                        and shell
                    )
                ):

                    emit(
                        "TAINT002",
                        node,
                        "Potential untrusted input reaches shell execution.",
                        Severity.HIGH,
                        "Avoid shell execution and use validated argument lists."
                    )

            for child in ast.iter_child_nodes(node):

                if not isinstance(child, ast.stmt):
                    inspect(child, env)

        # Construct control-flow edges and track taint.
        def block(body, env, incoming=()):

            env = set(env)

            exits = set(incoming)

            reachable = True

            for stmt in body:

                line = stmt.lineno

                # Detect unreachable statements.
                if not reachable:

                    emit(
                        "CFG001",
                        stmt,
                        "Statement is unreachable after an unconditional control transfer.",
                        Severity.MEDIUM,
                        "Remove unreachable code or revise control flow."
                    )

                    continue

                edges.update(
                    (previous, line)
                    for previous in exits
                )

                exits = {line}

                inspect(stmt, env)

                # Variable assignments.
                if isinstance(
                    stmt,
                    (
                        ast.Assign,
                        ast.AnnAssign,
                        ast.AugAssign
                    )
                ):

                    targets = (
                        stmt.targets
                        if isinstance(stmt, ast.Assign)
                        else [stmt.target]
                    )

                    dirty = tainted(stmt.value, env)

                    for target in targets:

                        if isinstance(target, ast.Name):

                            if dirty or (
                                isinstance(stmt, ast.AugAssign)
                                and target.id in env
                            ):

                                env.add(target.id)

                            else:

                                env.discard(target.id)

                # Conditional branches.
                elif isinstance(stmt, ast.If):

                    a, ae, ar = block(
                        stmt.body,
                        env,
                        exits
                    )

                    b, be, br = block(
                        stmt.orelse,
                        env,
                        exits
                    )

                    env = (
                        (a if ar else set())
                        | (b if br else set())
                    )

                    exits = ae | be

                    reachable = ar or br

                # Loops.
                elif isinstance(
                    stmt,
                    (
                        ast.For,
                        ast.AsyncFor,
                        ast.While
                    )
                ):

                    loop_env = set(env)

                    if (
                        isinstance(
                            stmt,
                            (ast.For, ast.AsyncFor)
                        )
                        and isinstance(stmt.target, ast.Name)
                        and tainted(stmt.iter, env)
                    ):

                        loop_env.add(stmt.target.id)

                    a, ae, _ = block(
                        stmt.body,
                        loop_env,
                        exits
                    )

                    # Approximate loop-carried taint.
                    a, ae, _ = block(
                        stmt.body,
                        a | loop_env,
                        exits
                    )

                    edges.update(
                        (previous, line)
                        for previous in ae
                    )

                    b, be, _ = block(
                        stmt.orelse,
                        env | a,
                        exits
                    )

                    env |= a | b

                    exits |= be

                # Unconditional control transfers.
                elif isinstance(
                    stmt,
                    (
                        ast.Return,
                        ast.Raise,
                        ast.Break,
                        ast.Continue
                    )
                ):

                    reachable = False

                    exits = set()

                # Context managers.
                elif isinstance(
                    stmt,
                    (ast.With, ast.AsyncWith)
                ):

                    env, exits, reachable = block(
                        stmt.body,
                        env,
                        exits
                    )

                # Exception handling.
                elif isinstance(
                    stmt,
                    (ast.Try, ast.TryStar)
                ):

                    a, ae, _ = block(
                        stmt.body,
                        env,
                        exits
                    )

                    b, be, _ = block(
                        stmt.orelse,
                        a,
                        ae
                    )

                    merged = env | a | b

                    for handler in stmt.handlers:

                        h, he, _ = block(
                            handler.body,
                            merged,
                            exits
                        )

                        merged |= h

                        be |= he

                    env, exits, _ = block(
                        stmt.finalbody,
                        merged,
                        be | exits
                    )

            return env, exits, reachable

        # Analyze module-level statements.
        block(tree.body, set())

        # Analyze individual function and class bodies.
        for node in ast.walk(tree):

            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef
                )
            ):

                block(node.body, set())

        metrics = {
            "edges": sorted(edges),
            "edge_count": len(edges)
        }

        return metrics, findings