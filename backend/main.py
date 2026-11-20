from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn
import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import VibeGuardScanner
from auto_patcher import VibeGuardAutoPatcher
from evaluate import run_evaluation
from benchmark_data import BENCHMARK_SNIPPETS

app = FastAPI(
    title="VibeGuard Security API",
    description="Zero-Latency Security Gate & Auto-Patcher for AI-Generated Code",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = VibeGuardScanner()
patcher = VibeGuardAutoPatcher()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_PATH = os.path.join(STATIC_DIR, "index.html")
PRESENTATION_PATH = os.path.join(STATIC_DIR, "presentation.html")

class ScanRequest(BaseModel):
    code: str
    language: Optional[str] = "python"

class PatchRequest(BaseModel):
    code: str
    findings: List[Dict[str, Any]]
    language: Optional[str] = "python"

class AstRequest(BaseModel):
    code: str

@app.get("/")
def get_ui():
    if os.path.exists(INDEX_PATH):
        return FileResponse(INDEX_PATH)
    return {"status": "online", "service": "VibeGuard AI Security Gate"}

@app.get("/presentation")
def get_presentation():
    if os.path.exists(PRESENTATION_PATH):
        return FileResponse(PRESENTATION_PATH)
    return {"detail": "Presentation file not found"}

@app.post("/api/scan")
def scan_code(req: ScanRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Empty code snippet provided.")
    result = scanner.scan_code(req.code, req.language)
    return result

@app.post("/api/autopatch")
def auto_patch(req: PatchRequest):
    result = patcher.patch_code(req.code, req.findings, req.language)
    # Automated post-patch verification re-scan
    verification = scanner.scan_code(result["patched_code"], req.language)
    result["verification"] = {
        "status": verification["status"],
        "findings_count": verification["findings_count"],
        "risk_score": verification.get("risk_score", 0),
        "verified_secure": verification["status"] == "CLEAN",
        "latency_ms": verification["latency_ms"]
    }
    return result

@app.post("/api/ast")
def get_ast(req: AstRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Empty code snippet provided.")
    return scanner.get_ast_tree(req.code)

@app.get("/api/benchmark")
def get_benchmark():
    summary = run_evaluation()
    return summary

@app.get("/api/presets")
def get_presets():
    return [
        {
            "id": "lovable-leak",
            "name": "Lovable: Leaked Supabase Service Role Key",
            "language": "python",
            "code": BENCHMARK_SNIPPETS[0]["code"].strip(),
            "description": "AI generated a client connection exposing the admin service_role secret directly in source code."
        },
        {
            "id": "sqli-idor",
            "name": "Cursor: SQL Injection + Missing Auth Check",
            "language": "python",
            "code": BENCHMARK_SNIPPETS[2]["code"].strip(),
            "description": "AI created a profile search endpoint with unescaped SQL string formatting."
        },
        {
            "id": "openai-key",
            "name": "v0: Hardcoded OpenAI Private Token",
            "language": "python",
            "code": BENCHMARK_SNIPPETS[3]["code"].strip(),
            "description": "AI hardcoded an active OpenAI private API key directly in the completion handler."
        },
        {
            "id": "clean-example",
            "name": "Clean: Secure Parameterized Endpoint",
            "language": "python",
            "code": BENCHMARK_SNIPPETS[18]["code"].strip(),
            "description": "Secure reference implementation using parameterized queries and zero hardcoded secrets."
        }
    ]

@app.get("/api/guide")
def get_security_guide():
    return [
        {
            "category": "API Keys & Hardcoded Secrets",
            "icon": "fa-key",
            "cwe": "CWE-798",
            "risk": "CRITICAL (CVSS 9.8)",
            "summary": "Never embed API tokens, service role keys, or database URLs in source code.",
            "rules": [
                "Store all credentials in a root '.env' file and add it to '.gitignore' immediately.",
                "In Python, load secrets using os.getenv('KEY') or python-dotenv.",
                "In JavaScript/Node, access secrets using process.env.KEY or Next.js public/private conventions.",
                "Use automated pre-commit scanning hooks like TruffleHog or GitGuardian to catch leaks before push.",
                "Use managed secret stores (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) in cloud environments."
            ],
            "bad_example": "client = Supabase('https://xyz.supabase.co', 'eyJhbGciOiJIUzI1NiIsIn...')",
            "good_example": "client = Supabase(os.getenv('SUPABASE_URL'), os.getenv('SUPABASE_SERVICE_ROLE_KEY'))"
        },
        {
            "category": "SQL Injection & ORM Safety",
            "icon": "fa-database",
            "cwe": "CWE-89",
            "risk": "HIGH (CVSS 8.8)",
            "summary": "Always separate SQL code structure from user data through parameterized binding.",
            "rules": [
                "Never use Python f-strings, % formatting, or JavaScript '+' concatenation inside raw SQL query strings.",
                "Use database driver placeholder tuples: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).",
                "In PostgreSQL / pg-promise, use positional placeholders: db.query('SELECT * FROM users WHERE id = $1', [id]).",
                "Prefer mature Object-Relational Mappers (ORM) like SQLAlchemy or Prisma with type-checked queries.",
                "Apply the principle of least privilege to database users (e.g. read-only roles where mutations are unnecessary)."
            ],
            "bad_example": "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
            "good_example": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
        },
        {
            "category": "Command Injection & Arbitrary Code Execution",
            "icon": "fa-terminal",
            "cwe": "CWE-78 / CWE-95",
            "risk": "CRITICAL (CVSS 9.8)",
            "summary": "Avoid spawning shell processes with dynamic user input.",
            "rules": [
                "Never call os.system() or eval() with user-controlled parameters.",
                "Use subprocess.run(['command', arg1, arg2], check=True, shell=False) so arguments are not interpreted by a shell.",
                "Sanitize any unavoidable shell parameters with shlex.quote() in Python.",
                "For parsing JSON or configuration data, always use json.loads() or ast.literal_eval() rather than eval()."
            ],
            "bad_example": "os.system(f'ping -c 1 {host_ip}')",
            "good_example": "subprocess.run(['ping', '-c', '1', host_ip], check=True, shell=False)"
        },
        {
            "category": "Broken Access Control & IDOR",
            "icon": "fa-user-shield",
            "cwe": "CWE-285",
            "risk": "HIGH (CVSS 7.5)",
            "summary": "Enforce authentication and resource ownership checks on every mutating API endpoint.",
            "rules": [
                "Always place authentication middleware or dependency injection (Depends(get_current_user)) on POST/PUT/DELETE routes.",
                "Never trust client-supplied user IDs from request parameters without checking if it matches the authenticated session.",
                "Implement Row-Level Security (RLS) policies at the database layer as a second line of defense.",
                "Audit API routes to ensure state-changing endpoints reject unauthenticated HTTP requests with 401/403."
            ],
            "bad_example": "@app.delete('/user/{user_id}')\ndef delete_account(user_id: int): db.delete(user_id)",
            "good_example": "@app.delete('/user/{user_id}')\ndef delete_account(user_id: int, current_user = Depends(get_current_user)):\n    if current_user.id != user_id: raise HTTPException(403)\n    db.delete(user_id)"
        }
    ]

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
