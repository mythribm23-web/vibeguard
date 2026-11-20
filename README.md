# VibeGuard 🛡️
> **Zero-Latency Real-Time Security Gate & Auto-Patcher for AI-Generated Code**  
> *The Big Hack 2.0 · Bengaluru | Track 3 (AI Research) · Problem R1: Vibe-coded and vulnerable*

---

## 📌 Problem Statement
80% of new developers build software by describing features in natural language to AI coding tools ("vibe coding"). However, AI-written code often introduces critical vulnerabilities:
1. **Hardcoded Secrets & API Keys** (OpenAI keys, Supabase service roles, DB passwords).
2. **Missing Access Control & Authorization** (IDOR, missing session validations, unprotected endpoints).
3. **Injection Flaws** (SQL injection via unescaped string formatting).

---

## 🎯 Our Hypothesis
> *"Security flaws in AI-generated code can be intercepted and remediated at generation time using deterministic Abstract Syntax Tree (AST) taint analysis and entropy heuristics, significantly reducing vulnerabilities with under 50ms latency overhead."*

---

## ⚡ Architecture: Three Deterministic Engines
- **Secret Detection Engine:** Pattern matching + Shannon entropy analysis for suspicious tokens and keys.
- **AST Taint Analyzer:** Analyzes code syntax trees locally without third-party LLMs to catch SQL injection and missing route auth guards.
- **1-Click Auto-Patcher:** Automatically generates secure replacements (parameterized queries, `.env` extractions) without breaking developer flow.
- **35+ Snippet Benchmark Suite:** Rigorous empirical evaluation comparing baseline AI generation vs VibeGuard.

---

## 🚀 Quick Start
### Run the Security Benchmark Locally
```bash
cd backend
python evaluate.py
```

### Run the Developer Studio (Web App)
```bash
cd backend
pip install -r requirements.txt
python main.py
```

---
*Built for India. Built in Bengaluru.*
