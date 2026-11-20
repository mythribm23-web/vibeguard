"""
VibeGuard Security Scanner Engine
Deterministic, generation-time static analysis combining:
1. Shannon Entropy & Regex-based secret detection
2. AST (Abstract Syntax Tree) taint & syntax analysis for injection flaws
3. Route authorization and access control validation
4. Compiler-level AST Node Hierarchy Extractor
"""

import ast
import re
import math
import time
from typing import List, Dict, Any, Optional

class ShannonEntropy:
    @staticmethod
    def calculate(text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

class VibeGuardScanner:
    def __init__(self):
        self.secret_patterns = [
            ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
            ("SUPABASE_KEY", re.compile(r"eyJhbGciOi[a-zA-Z0-9_\-\.]{30,}")),
            ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("GENERIC_API_TOKEN", re.compile(r"(?i)(api[_-]?key|secret|password|auth[_-]?token)\s*=\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]")),
            ("DATABASE_URL", re.compile(r"(postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-\.]+:[0-9]+")),
            ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}")),
        ]

    def scan_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        start_time = time.perf_counter()
        findings = []

        findings.extend(self._scan_secrets(code))

        if language.lower() in ["python", "py"]:
            findings.extend(self._scan_python_ast(code))
        else:
            findings.extend(self._scan_generic_code(code))

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        has_critical = any(f["severity"] == "CRITICAL" for f in findings)
        has_high = any(f["severity"] == "HIGH" for f in findings)
        status = "VULNERABLE" if (has_critical or has_high) else ("WARNING" if findings else "CLEAN")

        return {
            "status": status,
            "latency_ms": round(elapsed_ms, 2),
            "findings_count": len(findings),
            "findings": findings,
            "timestamp": time.time()
        }

    def _scan_secrets(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.split("\n")

        for idx, line in enumerate(lines, start=1):
            for secret_type, pattern in self.secret_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    val = match.group(0)
                    entropy = ShannonEntropy.calculate(val)
                    findings.append({
                        "id": f"VG-SEC-{secret_type}",
                        "cwe": "CWE-798",
                        "title": f"Hardcoded Secret / API Key ({secret_type})",
                        "line": idx,
                        "severity": "CRITICAL",
                        "snippet": line.strip(),
                        "entropy": round(entropy, 2),
                        "description": f"Exposed secret detected on line {idx}.",
                        "fix_suggestion": "Extract the secret into an environment variable."
                    })

            string_literals = re.findall(r"['\"]([a-zA-Z0-9_\-\.]{24,})['\"]", line)
            for s in string_literals:
                entropy = ShannonEntropy.calculate(s)
                if entropy > 4.2 and not any(p in line for p in ["import", "from", "def", "class"]):
                    if not any(f["line"] == idx and "Secret" in f["title"] for f in findings):
                        findings.append({
                            "id": "VG-SEC-HIGH-ENTROPY",
                            "cwe": "CWE-798",
                            "title": "High-Entropy Suspicious Literal Detected",
                            "line": idx,
                            "severity": "CRITICAL",
                            "snippet": line.strip(),
                            "entropy": round(entropy, 2),
                            "description": f"Detected string with Shannon Entropy of {round(entropy, 2)}.",
                            "fix_suggestion": "Move token to .env.local configuration file."
                        })

        return findings

    def _scan_python_ast(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._scan_generic_code(code)

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.local_findings = []

            def visit_Call(self, node):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ["execute", "raw", "query", "raw_query"]:
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                            self.local_findings.append({
                                "id": "VG-INJ-SQLI",
                                "cwe": "CWE-89",
                                "title": "SQL Injection via String Concatenation",
                                "line": node.lineno,
                                "severity": "HIGH",
                                "description": "Database query constructed using string concatenation.",
                                "fix_suggestion": "Use parameterized queries ($1, ? or :param).",
                                "taint_flow": {
                                    "source": "Untrusted request parameter",
                                    "intermediate": "String concatenation BinOp (+)",
                                    "sink": f"Database execution sink: {func_name}()"
                                }
                            })
                        elif isinstance(first_arg, ast.JoinedStr):
                            self.local_findings.append({
                                "id": "VG-INJ-SQLI-FSTRING",
                                "cwe": "CWE-89",
                                "title": "SQL Injection via Formatted String (f-string)",
                                "line": node.lineno,
                                "severity": "HIGH",
                                "description": "Raw SQL query uses interpolated f-string.",
                                "fix_suggestion": "Pass query parameters separately to database driver.",
                                "taint_flow": {
                                    "source": "Interpolated f-string variable",
                                    "intermediate": "ast.JoinedStr dynamic evaluation",
                                    "sink": f"Database execution sink: {func_name}()"
                                }
                            })

                if func_name in ["system", "popen", "check_output"]:
                    if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                        self.local_findings.append({
                            "id": "VG-INJ-RCE",
                            "cwe": "CWE-78",
                            "title": "Command Injection Risk via Dynamic Shell Execution",
                            "line": node.lineno,
                            "severity": "CRITICAL",
                            "description": "System command execution with dynamic user input leads to RCE.",
                            "fix_suggestion": "Avoid shell=True and pass command arguments as a list.",
                            "taint_flow": {
                                "source": "User command arguments",
                                "intermediate": "Direct shell interpolation",
                                "sink": f"OS execution sink: os.{func_name}()"
                            }
                        })

                if func_name in ["eval", "exec"]:
                    self.local_findings.append({
                        "id": "VG-RCE-EVAL",
                        "cwe": "CWE-95",
                        "title": "Arbitrary Code Execution via eval() / exec()",
                        "line": node.lineno,
                        "severity": "CRITICAL",
                        "description": "Dynamic evaluation of untrusted code leads to system compromise.",
                        "fix_suggestion": "Refactor logic to use safe parsers like json.loads.",
                        "taint_flow": {
                            "source": "Untrusted user expression string",
                            "intermediate": "Dynamic code evaluator",
                            "sink": f"{func_name}() runtime compilation"
                        }
                    })

                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                func_name_lower = node.name.lower()
                is_mutating = any(action in func_name_lower for action in ["delete", "update", "patch", "modify", "remove"])
                
                has_auth = False
                for decorator in node.decorator_list:
                    d_name = ""
                    if isinstance(decorator, ast.Name):
                        d_name = decorator.id.lower()
                    elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                        d_name = decorator.func.id.lower()
                    if any(term in d_name for term in ["auth", "login_required", "protect", "security", "permission"]):
                        has_auth = True

                for stmt in ast.walk(node):
                    if isinstance(stmt, ast.Name) and stmt.id in ["user", "session", "current_user", "auth", "token"]:
                        has_auth = True

                if is_mutating and not has_auth:
                    self.local_findings.append({
                        "id": "VG-AUTH-IDOR",
                        "cwe": "CWE-285",
                        "title": "Missing Access Control on Mutating Endpoint (IDOR)",
                        "line": node.lineno,
                        "severity": "HIGH",
                        "description": f"Endpoint '{node.name}' performs mutations without verifying authorization.",
                        "fix_suggestion": "Add authentication dependency / session check.",
                        "taint_flow": {
                            "source": f"HTTP Mutation Route /{node.name}",
                            "intermediate": "Direct invocation without session assertion",
                            "sink": "Database state mutation"
                        }
                    })

                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)
        findings.extend(visitor.local_findings)
        return findings

    def _scan_generic_code(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.split("\n")

        for idx, line in enumerate(lines, start=1):
            if any(term in line for term in ["query(", "execute(", "db.$queryRaw", "SELECT", "INSERT", "UPDATE", "DELETE"]):
                if re.search(r"\+.*req\.(body|query|params)|`.*\$\{req\.", line):
                    findings.append({
                        "id": "VG-INJ-SQLI-JS",
                        "cwe": "CWE-89",
                        "title": "SQL Injection via Concatenation / Template Literal",
                        "line": idx,
                        "severity": "HIGH",
                        "snippet": line.strip(),
                        "description": "Database query constructed using unescaped request input.",
                        "fix_suggestion": "Use parameterized queries or ORM prepared statements.",
                        "taint_flow": {
                            "source": "req.params / req.body",
                            "intermediate": "Template literal interpolation (${...})",
                            "sink": "Database query execution sink"
                        }
                    })

            if re.search(r"app\.(post|put|delete|patch)\(['\"].*['\"],\s*async?\s*\((req,\s*res|request)\)", line):
                if not any(token in line for token in ["requireAuth", "verifyToken", "authenticate", "authMiddleware", "protect"]):
                    findings.append({
                        "id": "VG-AUTH-UNPROTECTED-ROUTE",
                        "cwe": "CWE-306",
                        "title": "Unauthenticated API Mutation Route (Missing Auth Guard)",
                        "line": idx,
                        "severity": "HIGH",
                        "snippet": line.strip(),
                        "description": "API route handles sensitive modifications without authentication middleware.",
                        "fix_suggestion": "Mount an authentication middleware handler on the route.",
                        "taint_flow": {
                            "source": "Public HTTP endpoint",
                            "intermediate": "Missing authentication middleware",
                            "sink": "Unauthenticated database modification"
                        }
                    })

            if "dangerouslySetInnerHTML" in line or "innerHTML" in line:
                if not any(sanitize in line for sanitize in ["DOMPurify", "sanitize"]):
                    findings.append({
                        "id": "VG-XSS-UNSANITIZED",
                        "cwe": "CWE-79",
                        "title": "Cross-Site Scripting (XSS) via Unsanitized HTML",
                        "line": idx,
                        "severity": "HIGH",
                        "snippet": line.strip(),
                        "description": "Direct insertion of unsanitized HTML into DOM permits script execution.",
                        "fix_suggestion": "Pass raw strings through DOMPurify.sanitize().",
                        "taint_flow": {
                            "source": "Untrusted HTML input string",
                            "intermediate": "Raw unescaped rendering",
                            "sink": "Browser DOM execution context"
                        }
                    })

        return findings

    def get_ast_tree(self, code: str) -> Dict[str, Any]:
        """Parses code into hierarchical AST tree representation for visual inspection."""
        try:
            tree = ast.parse(code)
        except Exception as e:
            return {"error": f"Failed to parse AST: {str(e)}"}

        def node_to_dict(node):
            node_type = type(node).__name__
            info = {"type": node_type}
            if hasattr(node, "lineno"):
                info["line"] = node.lineno
            if hasattr(node, "name"):
                info["name"] = node.name
            if hasattr(node, "id"):
                info["id"] = node.id

            children = []
            for child in ast.iter_child_nodes(node):
                children.append(node_to_dict(child))
            if children:
                info["children"] = children[:6] # Limit depth/breadth for clean UI display
            return info

        return node_to_dict(tree)
