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
    version="1.0.0"
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
