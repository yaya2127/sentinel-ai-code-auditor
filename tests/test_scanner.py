import unittest
from core.ast_parser import ASTSecurityScanner
from core.agentic_reasoner import AgenticAIReasoner

class TestASTSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ASTSecurityScanner()
        self.reasoner = AgenticAIReasoner()

    def test_sql_injection_detection(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")'
        vulns = self.scanner.scan_file("test.py", code)
        self.assertTrue(len(vulns) > 0)
        self.assertEqual(vulns[0]["vuln_type"], "SQL_INJECTION")

    def test_hardcoded_secret_detection(self):
        code = 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY"'
        vulns = self.scanner.scan_file("test.py", code)
        self.assertTrue(len(vulns) > 0)
        self.assertEqual(vulns[0]["vuln_type"], "HARDCODED_SECRET")

    def test_buffer_overflow_detection(self):
        code = "strcpy(buffer, input);"
        vulns = self.scanner.scan_file("test.cpp", code)
        self.assertTrue(len(vulns) > 0)
        self.assertEqual(vulns[0]["vuln_type"], "BUFFER_OVERFLOW")

    def test_patch_synthesis(self):
        vuln = {
            "vuln_id": "VULN-TEST-01",
            "file_path": "test.py",
            "line_number": 1,
            "vuln_type": "SQL_INJECTION",
            "vulnerable_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")'
        }
        patch = self.reasoner.synthesize_fix(vuln, vuln["vulnerable_snippet"])
        self.assertIn("SELECT * FROM users", patch["patched_code"])

if __name__ == '__main__':
    unittest.main()
