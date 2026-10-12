import json
import streamlit as st
from codesage.analyzer import analyze_code, make_report

st.set_page_config(page_title="CodeSage AI", page_icon="🧠", layout="wide")
st.title("🧠 CodeSage AI")
st.caption("Explainable Python code review • Security signals • Bug-risk triage")
st.info("Local-first static analysis. Your code is not sent to an external AI service. The score is a heuristic, not a guarantee.")

with st.sidebar:
    strict = st.toggle("Strict review", value=False)
    style = st.toggle("Include style recommendations", value=True)
    st.markdown("**Engine:** Python AST + explainable rules")
    st.markdown("**Language:** Python")

sample = "import pickle\n\ndef load_data(path, items=[]):\n    password = \"admin123\"\n    data = pickle.loads(open(path, \"rb\").read())\n    print(data)\n    return items\n"
code = st.text_area("Paste Python code", value=sample, height=320)
uploaded = st.file_uploader("Or upload a .py file", type=["py"])
if uploaded:
    try:
        code = uploaded.read().decode("utf-8")
        st.success("File loaded.")
    except UnicodeDecodeError:
        st.error("File must be UTF-8 encoded.")

if st.button("🔍 Review code", type="primary", use_container_width=True):
    if not code.strip():
        st.warning("Paste or upload Python code first.")
    else:
        st.session_state.result = analyze_code(code, strict, style)

if "result" in st.session_state:
    result = st.session_state.result
    st.divider()
    a, b, c, d = st.columns(4)
    a.metric("Risk score", f'{result["risk_score"]}/100')
    b.metric("Findings", len(result["findings"]))
    c.metric("Lines", result["metrics"]["lines"])
    d.metric("Approx. complexity", result["metrics"]["complexity"])
    if result["risk_score"] >= 70:
        st.error("High review risk. Address critical/high findings first.")
    elif result["risk_score"] >= 35:
        st.warning("Moderate review risk. Inspect findings below.")
    else:
        st.success("Low rule-based risk. Still run tests and review manually.")
    st.subheader("Prioritized findings")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings = sorted(result["findings"], key=lambda x: (order.get(x["severity"], 5), x["line"] or 0))
    if not findings:
        st.success("No findings matched the current rules.")
    for f in findings:
        label = f'{f["severity"]} · {f["title"]}' + (f' · Line {f["line"]}' if f["line"] else "")
        with st.expander(label, expanded=f["severity"] in ("Critical", "High")):
            st.write(f["description"])
            st.markdown("**Why it matters:** " + f["impact"])
            st.markdown("**Suggested fix:** " + f["fix"])
            st.caption("Rule ID: " + f["rule_id"])
    st.subheader("Code metrics")
    st.write(result["summary"])
    st.json(result["metrics"])
    st.download_button("Download Markdown report", make_report(result), "codesage-review-report.md", "text/markdown")
    st.download_button("Download JSON findings", json.dumps(result, indent=2), "codesage-findings.json", "application/json")
