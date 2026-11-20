import uvicorn
import os
import sys

backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.insert(0, backend_dir)

if __name__ == "__main__":
    print("=" * 65)
    print(" 🛡️  STARTING VIBEGUARD AI CODE SECURITY STUDIO")
    print(" Track 3 (AI Research) · Problem R1: Vibe-coded and vulnerable")
    print(" Studio UI available at: http://127.0.0.1:8000")
    print(" Swagger Docs available at: http://127.0.0.1:8000/docs")
    print("=" * 65)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, app_dir=backend_dir)
