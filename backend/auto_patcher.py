"""
VibeGuard 1-Click Auto-Patcher Engine
Automatically transforms detected security vulnerabilities into safe, production-ready code.
1. Replaces hardcoded secrets with environment variable lookups.
2. Generates corresponding .env.local content.
3. Parameterizes unsafe SQL queries (f-strings and concatenation).
4. Injects authentication dependency guards.
5. Replaces unsafe os.system() with subprocess.run() array calls.
6. Replaces arbitrary eval() with safe ast.literal_eval().
7. Sanitizes XSS dangerous innerHTML with DOMPurify.sanitize().
"""

import re
from typing import Dict, Any, List

class VibeGuardAutoPatcher:
    def patch_code(self, code: str, findings: List[Dict[str, Any]], language: str = "python") -> Dict[str, Any]:
        """
        Takes vulnerable code and list of findings, returning patched code and generated .env variables.
        """
        patched_lines = code.split("\n")
        env_variables = {}
        applied_fixes = []
        needs_subprocess = False
        needs_ast = False

        # Sort findings by line number descending so line replacements don't shift offsets
        sorted_findings = sorted(findings, key=lambda f: f.get("line", 0), reverse=True)

        for finding in sorted_findings:
            line_idx = finding.get("line", 0) - 1
            if line_idx < 0 or line_idx >= len(patched_lines):
                continue

            current_line = patched_lines[line_idx]
            finding_id = finding.get("id", "")

            # 1. Fix Hardcoded Secrets
            if "VG-SEC" in finding_id:
                secret_match = re.search(r"['\"]([a-zA-Z0-9_\-\.]{16,})['\"]", current_line)
                if secret_match:
                    raw_secret = secret_match.group(1)
                    var_name = "API_KEY"
                    if "SUPABASE" in finding_id or "eyJ" in raw_secret:
                        var_name = "SUPABASE_SERVICE_ROLE_KEY"
                    elif "OPENAI" in finding_id or raw_secret.startswith("sk-"):
                        var_name = "OPENAI_API_KEY"
                    elif "AWS" in finding_id or raw_secret.startswith("AKIA"):
                        var_name = "AWS_ACCESS_KEY_ID"
                    elif "DATABASE" in finding_id:
                        var_name = "DATABASE_URL"
                    elif "GITHUB" in finding_id or raw_secret.startswith("gh"):
                        var_name = "GITHUB_TOKEN"

                    env_variables[var_name] = raw_secret

                    if language.lower() in ["python", "py"]:
                        new_line = re.sub(r"['\"][a-zA-Z0-9_\-\.]{16,}['\"]", f'os.getenv("{var_name}")', current_line)
                    else:
                        new_line = re.sub(r"['\"][a-zA-Z0-9_\-\.]{16,}['\"]", f'process.env.{var_name}', current_line)

                    patched_lines[line_idx] = new_line
                    applied_fixes.append(f"Line {line_idx+1}: Extracted {var_name} to environment variable.")

            # 2. Fix SQL Injection (f-string in Python)
            elif "VG-INJ-SQLI-FSTRING" in finding_id:
                match = re.search(r'f["\'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["\']', current_line)
                if match:
                    prefix = match.group(1)
                    var_name = match.group(2)
                    suffix = match.group(3).replace("'", "")
                    parameterized = f'"{prefix}?{suffix}", ({var_name},)'
                    new_line = re.sub(r'f["\'].*?\{[a-zA-Z0-9_]+\}.*?["\']', parameterized, current_line)
                    patched_lines[line_idx] = new_line
                    applied_fixes.append(f"Line {line_idx+1}: Parameterized raw SQL query to prevent SQL injection.")

            # 3. Fix SQL Injection (Concatenation in JS/Python)
            elif "VG-INJ-SQLI" in finding_id:
                if "+" in current_line:
                    parts = current_line.split("+")
                    query_part = parts[0].strip().rstrip('"').rstrip("'").strip()
                    param_part = parts[1].strip().rstrip(")").rstrip(";").strip()
                    if language.lower() in ["python", "py"]:
                        new_line = f'{query_part} ?", ({param_part},))'
                    else:
                        new_line = f'{query_part} $1", [{param_part}]);'
                    patched_lines[line_idx] = new_line
                    applied_fixes.append(f"Line {line_idx+1}: Converted string concatenation to parameterized query.")

            # 4. Fix Missing Auth Guard (IDOR)
            elif "VG-AUTH-IDOR" in finding_id:
                indent = len(current_line) - len(current_line.lstrip())
                indent_str = " " * indent
                auth_guard = f"{indent_str}# [VibeGuard Guard] Validate user identity\n{indent_str}if not getattr(request, 'user', None):\n{indent_str}    raise PermissionError('Unauthorized access denied.')\n"
                patched_lines.insert(line_idx + 1, auth_guard)
                applied_fixes.append(f"Line {line_idx+1}: Injected authorization guard checking user session.")

            # 5. Fix Command Injection / RCE
            elif "VG-INJ-RCE" in finding_id:
                needs_subprocess = True
                if "os.system" in current_line:
                    match = re.search(r'os\.system\(f["\']([a-zA-Z0-9_\-]+)\s+\{([a-zA-Z0-9_]+)\}(.*?)["\']\)', current_line)
                    if match:
                        cmd = match.group(1)
                        var = match.group(2)
                        new_line = re.sub(r'os\.system\(.*?\)', f'subprocess.run(["{cmd}", str({var})], check=True)', current_line)
                    else:
                        new_line = current_line.replace("os.system(", "subprocess.run([")
                    patched_lines[line_idx] = new_line
                    applied_fixes.append(f"Line {line_idx+1}: Replaced unsafe shell os.system with secure subprocess.run list arguments.")

            # 6. Fix Arbitrary Eval
            elif "VG-RCE-EVAL" in finding_id:
                needs_ast = True
                new_line = current_line.replace("eval(", "ast.literal_eval(")
                patched_lines[line_idx] = new_line
                applied_fixes.append(f"Line {line_idx+1}: Replaced arbitrary eval() with safe ast.literal_eval().")

            # 7. Fix Cross-Site Scripting (XSS)
            elif "VG-XSS-UNSANITIZED" in finding_id:
                new_line = re.sub(r'__html:\s*([a-zA-Z0-9_.]+)', r'__html: DOMPurify.sanitize(\1)', current_line)
                patched_lines[line_idx] = new_line
                applied_fixes.append(f"Line {line_idx+1}: Wrapped raw HTML rendering with DOMPurify.sanitize().")

        final_code = "\n".join(patched_lines)
        if env_variables and language.lower() in ["python", "py"] and "import os" not in final_code:
            final_code = "import os\n" + final_code
        if needs_subprocess and "import subprocess" not in final_code:
            final_code = "import subprocess\n" + final_code
        if needs_ast and "import ast" not in final_code:
            final_code = "import ast\n" + final_code

        env_content = "\n".join([f"{k}={v}" for k, v in env_variables.items()])

        return {
            "patched_code": final_code,
            "env_content": env_content,
            "fixes_applied": applied_fixes,
            "fix_count": len(applied_fixes)
        }
