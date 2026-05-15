"""
main.py
────────
Entry point. Run with:
    python main.py
or:
    uvicorn main:app --reload --port 8000
"""

import uvicorn
from backend.api.app import app  # noqa: F401 — exported for uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug",
    )
