import ast
import re

WEIGHTS = {"Critical": 30, "High": 18, "Medium": 9, "Low": 4, "Info": 0}

def finding(rule, severity, title, line, description, impact, fix):
    return {"rule_id": rule, "severity": severity, "title": title, "line": line or None,
            "description": description, "impact": impact, "fix": fix}

def analyze_code(code, strict=False, include_style=True):
    lines = code.splitlines()
    findings = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        findings.append(finding("PY001", "Critical", "Python syntax error", exc.lineno or 1,
            exc.msg, "The file may not run at all.", "Fix the syntax error and run python -m py_compile your_file.py."))
        return {"risk_score": 100, "findings": findings, "metrics": metrics(lines, [], [], 0, 0),
                "summary": "Analysis stopped because Python could not parse this file."}

    def add(*args):
        findings.append(finding(*args))

    funcs, classes, imports = [], [], 0
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(node)
            if include_style and len(node.body) > (12 if strict else 20):
                add("ST101", "Medium", "Long function", node.lineno,
                    f"Function {node.name} has {len(node.body)} top-level statements.",
                    "Long functions are harder to test and maintain.",
                    "Split the function into smaller units with one responsibility.")
            if node.args.defaults:
                args = node.args.args[-len(node.args.defaults):]
                for arg, default in zip(args, node.args.defaults):
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        add("PY002", "High", "Mutable default argument", node.lineno,
                            f"Parameter {arg.arg} uses a mutable default.",
                            "The same object may be reused between calls, causing state leakage.",
                            "Use None as the default and create the object inside the function.")
        elif isinstance(node, ast.ClassDef):
            classes.append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imports += 1
        elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)

    rules = [
        (r'(?i)\b(password|passwd|api[_-]?key|secret|token)\s*=\s*[\'"][^\'"]{4,}[\'"]',
         "SEC001", "High", "Possible hard-coded secret", "A credential-like value appears directly in source.",
         "It may be exposed in source control or logs.", "Use environment variables or a secret manager; rotate real exposed credentials."),
        (r'\bpickle\.(loads|load)\s*\(', "SEC002", "Critical", "Unsafe pickle deserialization",
         "Pickle can execute attacker-controlled code during deserialization.",
         "Untrusted pickle data can lead to arbitrary code execution.", "Never load untrusted pickle data; prefer a safe validated format such as JSON."),
        (r'\beval\s*\(', "SEC003", "High", "Use of eval()", "eval() evaluates a string as Python code.",
         "Untrusted input can become code execution.", "Replace eval with explicit parsing or an allowlist of operations."),
        (r'\bexec\s*\(', "SEC004", "High", "Use of exec()", "exec() executes dynamic Python statements.",
         "Dynamic execution increases injection risk.", "Avoid exec and use explicit functions and validated data."),
        (r'\bos\.system\s*\(', "SEC005", "High", "Shell command execution", "os.system() invokes a shell command.",
         "Untrusted content may cause command injection.", "Prefer subprocess.run with a list of arguments and shell=False."),
        (r"""(?i)select\s+.+\s+from\s+.+\s+where\s+.+['"]\s*\+""", "SEC006", "High",
         "Possible SQL string concatenation", "A SQL query may be assembled by concatenating values.",
         "Untrusted values can alter the query.", "Use parameterized queries instead of string concatenation."),
        (r'\bexcept\s*:', "PY003", "Medium", "Bare except clause", "A bare except catches almost every exception.",
         "Unexpected failures can be hidden.", "Catch specific exception types and handle them deliberately."),
        (r'\bprint\s*\(', "ST102", "Low", "Print statement in application code", "A print() may be leftover debugging output.",
         "It can clutter logs or expose information.", "Use the logging module with appropriate log levels.")
    ]
    seen = set()
    for n, line in enumerate(lines, 1):
        for pattern, rid, sev, title, desc, impact, fix in rules:
            if re.search(pattern, line):
                if (rid, n) not in seen:
                    add(rid, sev, title, n, desc, impact, fix)
                    seen.add((rid, n))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            inside_with = any(isinstance(p, (ast.With, ast.AsyncWith)) and p.lineno <= node.lineno <= getattr(p, "end_lineno", p.lineno) for p in ast.walk(tree))
            if not inside_with:
                add("PY004", "Low", "File opened outside a with block", node.lineno,
                    "open() appears outside a surrounding with statement.",
                    "The file may not be closed promptly after errors.",
                    "Use with open(path, mode) as file: to close it reliably.")

    if include_style:
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.For, ast.While)):
                depth = nesting_depth(tree, node)
                if depth >= (4 if strict else 5):
                    add("ST103", "Medium", "Deeply nested control flow", node.lineno,
                        f"This block is nested approximately {depth} levels deep.",
                        "Deep nesting makes logic harder to understand and test.",
                        "Use guard clauses, early returns, or extract a helper function.")

    met = metrics(lines, funcs, classes, imports, complexity)
    high = sum(x["severity"] in ("Critical", "High") for x in findings)
    score = min(100, sum(WEIGHTS.get(x["severity"], 0) for x in findings))
    summary = f"Found {len(findings)} potential issue(s), including {high} critical/high-severity finding(s). Review fixes and run tests."
    return {"risk_score": score, "findings": findings, "metrics": met, "summary": summary}

def metrics(lines, funcs, classes, imports, complexity):
    return {"lines": len(lines), "functions": len(funcs), "classes": len(classes), "imports": imports,
            "complexity": complexity,
            "longest_function": max((getattr(f, "end_lineno", f.lineno) - f.lineno + 1 for f in funcs), default=0)}

def nesting_depth(tree, target):
    result = 0
    def visit(node, depth):
        nonlocal result
        if node is target:
            result = max(result, depth)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, depth + int(isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith))))
    visit(tree, 0)
    return result

def make_report(result):
    m = result["metrics"]
    out = ["# CodeSage AI — Code Review Report", "", f'**Risk score:** {result["risk_score"]}/100',
           f'**Lines:** {m["lines"]} · **Functions:** {m["functions"]} · **Classes:** {m["classes"]} · **Approx. complexity:** {m["complexity"]}',
           "", "## Summary", result["summary"], "", "## Findings"]
    if not result["findings"]:
        out.append("No findings matched the configured rules.")
    for f in result["findings"]:
        line = f' (line {f["line"]})' if f["line"] else ""
        out += [f'### [{f["severity"]}] {f["title"]}{line}', f'**Rule:** `{f["rule_id"]}`', "",
                f["description"], "", f'**Why it matters:** {f["impact"]}', "", f'**Suggested fix:** {f["fix"]}', ""]
    out += ["## Limitations", "This is rule-based static analysis, not proof of correctness or a replacement for tests, peer review, dependency scanning, or a security audit."]
    return "\n".join(out)
