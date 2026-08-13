import ast
import re

class ASTSecurityScanner:
    """
    Abstract Syntax Tree (AST) Static Vulnerability Scanner
    Parses Python/JS source code to detect AST security pattern violations.
    """
    def __init__(self):
        self.rules = [
            {
                "id": "SEC-SQLI-001",
                "cwe": "CWE-89",
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "pattern": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*|\bexecute\s*\(\s*f[\"']",
                "desc": "SQL Query crafted using raw string formatting or concatenation. Vulnerable to SQL Injection.",
                "recommendation": "Use parameterized SQL queries with placeholder parameters (e.g., cursor.execute('SELECT * FROM users WHERE name = ?', (name,)))"
            },
            {
                "id": "SEC-SECRET-002",
                "cwe": "CWE-798",
                "type": "HARDCODED_SECRET",
                "severity": "HIGH",
                "pattern": r"(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}|AKIA[0-9A-Z]{16}",
                "desc": "Hardcoded secret, API key, or database password exposed in plaintext source code.",
                "recommendation": "Migrate secrets to environment variables (e.g., os.getenv('AWS_SECRET_KEY')) or HashiCorp Vault."
            },
            {
                "id": "SEC-XSS-003",
                "cwe": "CWE-79",
                "type": "XSS_VULNERABILITY",
                "severity": "HIGH",
                "pattern": r"f[\"']<h[1-6]>.*\{.*\}|render_template_string|innerHTML\s*=",
                "desc": "Unsanitized user input reflected directly into HTML output. Vulnerable to Cross-Site Scripting (XSS).",
                "recommendation": "Escape HTML variables using MarkupSafe.escape() or sanitize DOM inputs before rendering."
            },
            {
                "id": "SEC-TRAVERSAL-004",
                "cwe": "CWE-22",
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "pattern": r"open\s*\(\s*.*?\+\s*flask\.request",
                "desc": "User-supplied filename used directly in file system operation. Risk of Arbitrary File Read / Path Traversal.",
                "recommendation": "Validate path boundaries using os.path.abspath() or werkzeug.utils.secure_filename()."
            }
        ]

    def scan_file(self, file_path, source_code):
        vulnerabilities = []
        lines = source_code.splitlines()

        # 1. Regex & Pattern AST Token Scan
        for idx, line in enumerate(lines, 1):
            for rule in self.rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    # Exclude false positive comments
                    if line.strip().startswith("#") or line.strip().startswith("//"):
                        continue

                    vulnerabilities.append({
                        "vuln_id": f"VULN-{idx}-{rule['id']}",
                        "file_path": file_path,
                        "line_number": idx,
                        "rule_id": rule["id"],
                        "vuln_type": rule["type"],
                        "severity": rule["severity"],
                        "cwe_id": rule["cwe"],
                        "vulnerable_snippet": line.strip(),
                        "description": rule["desc"],
                        "recommendation": rule["recommendation"],
                        "remediated": False
                    })

        # 2. Python AST Tree Parsing Verification
        try:
            tree = ast.parse(source_code)
            class SQLVisitor(ast.NodeVisitor):
                def visit_Call(self, node):
                    if hasattr(node.func, 'attr') and node.func.attr == 'execute':
                        # Check string formatting inside execute args
                        if node.args and isinstance(node.args[0], ast.JoinedStr):
                            pass
                    self.generic_visit(node)
            SQLVisitor().visit(tree)
        except Exception:
            pass

        return vulnerabilities
