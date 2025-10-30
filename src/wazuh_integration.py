#!/usr/bin/env python3
import sys, json, os, requests

API = os.getenv("EXPLAIN_API", "http://127.0.0.1:8080/explain")

def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print("No input")
        return 1
    try:
        alert = json.loads(raw)
    except Exception as e:
        print("Bad JSON:", e)
        return 2
    try:
        r = requests.post(API, json={"alert": alert}, timeout=5)
        print("[explainer]", r.status_code, r.text)
        return 0
    except Exception as e:
        print("[explainer] POST failed:", e)
        return 3

if __name__ == "__main__":
    sys.exit(main())
