#!/usr/bin/env python3
import sys, json, os, requests

API_URL = os.environ.get("EXPLAIN_API", "http://127.0.0.1:8989/score_explain")

def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("No input", file=sys.stderr); return 1

    try:
        payload = json.loads(raw)
    except Exception as e:
        print(f"Bad JSON: {e}", file=sys.stderr); return 2

    # Wazuh integration payloads usually pack the alert under `full_log` or `alert`
    alert = payload.get("alert") or payload.get("full_log")
    if isinstance(alert, str):
        try: alert = json.loads(alert)
        except: alert = {}

    alert_id = (alert.get("id") or alert.get("event", {}).get("id") or "unknown")
    body = {"alert_id": str(alert_id), "alert": alert}

    try:
        r = requests.post(API_URL, json=body, timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"[explain] POST failed: {e}", file=sys.stderr); return 3

    # Optional: write a tiny marker line so you can grep wazuh-logs
    print(f"[explain] stored explanation for alert_id={alert_id}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
