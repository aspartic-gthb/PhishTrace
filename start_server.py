#!/usr/bin/env python3
"""
PhishTrace / Forensic Intelligence Platform Server Launcher
Starts FastAPI backend server on port 8005.
"""
import os
import sys
import uvicorn

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
os.environ["PYTHONIOENCODING"] = "utf-8"

if __name__ == "__main__":
    print(f"Starting Forensic Intelligence Platform Backend from {PROJECT_ROOT} on port 8005")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8005, reload=False)
