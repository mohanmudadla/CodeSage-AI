# CodeSage AI — Intelligent Python Code Review

A portfolio-ready static-analysis web app that reviews Python code for security risks, correctness pitfalls, maintainability concerns, and complexity signals. It provides prioritized findings with explanations and fixes, plus Markdown and JSON exports.

**Honest scope:** This version uses Python's AST parser and explainable static-analysis rules. It does not call an LLM. Its risk score is a heuristic—not a probability of bugs and not a guarantee of security.

## Features
- Python syntax validation with line numbers
- Checks for possible hard-coded secrets, unsafe `pickle`, `eval`, `exec`, shell execution, and SQL string concatenation
- Mutable-default, broad-exception, file-handling, long-function, and nesting checks
- Complexity and code metrics
- Severity-prioritized findings with remediation guidance
- Downloadable Markdown and JSON reports
- Local-first: no API key required
- Unit tests

## Run on Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, use Command Prompt and run `.venv\Scripts\activate.bat` instead. Open the local URL printed in the terminal, usually `http://localhost:8501`.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Structure

```text
CodeSage-AI/
├── app.py
├── codesage/
│   ├── __init__.py
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## How it works
1. `ast.parse()` validates Python syntax and creates an abstract syntax tree.
2. AST traversal calculates approximate code metrics and checks structural patterns.
3. Source rules detect suspicious security and maintainability patterns.
4. Each finding includes a severity, explanation, impact, and suggested fix.
5. A weighted score capped at 100 helps prioritize manual review.

## Limitations
Pattern matching can create false positives and miss issues. The complexity value is approximate. Use tests, peer review, dependency scanning, and tools such as Bandit alongside this app. Do not paste real secrets or proprietary source code into public demos.

## Roadmap
- Add Bandit integration
- Add GitHub Actions CI
- Add repository-level batch analysis and historical reports
- Add an optional LLM explanation layer with explicit consent and secure secret handling

## Suggested GitHub topics
`python` `streamlit` `static-analysis` `code-review` `application-security` `developer-tools` `ai-project`

## License
MIT.
