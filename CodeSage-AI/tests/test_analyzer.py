import unittest
from codesage.analyzer import analyze_code, make_report

class AnalyzerTests(unittest.TestCase):
    def test_syntax_error(self):
        self.assertEqual(analyze_code("def broken(:")["findings"][0]["rule_id"], "PY001")
    def test_mutable_default(self):
        result = analyze_code("def f(items=[]):\n    return items")
        self.assertIn("PY002", [f["rule_id"] for f in result["findings"]])
    def test_pickle_warning(self):
        result = analyze_code("import pickle\ndata = pickle.loads(blob)")
        self.assertIn("SEC002", [f["rule_id"] for f in result["findings"]])
    def test_report(self):
        self.assertIn("# CodeSage AI", make_report(analyze_code("x = 1")))

if __name__ == "__main__":
    unittest.main()
