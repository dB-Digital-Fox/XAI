# src/tools/validate_policy.py
from __future__ import annotations
import sys, yaml

REQUIRED = {"thresholds","rules","triage_text","recommendations"}

def main(path):
    y = yaml.safe_load(open(path, "r", encoding="utf-8"))
    missing = REQUIRED - set(y.keys())
    if missing:
        print(f"Missing keys: {missing}"); sys.exit(1)
    # sanity check thresholds order
    th = y["thresholds"]; vals = [th.get(k,0) for k in ("info","low","medium","high","critical") if k in th]
    if sorted(vals) != vals:
        print("Thresholds not non-decreasing (info ≤ low ≤ medium ≤ high ≤ critical)."); sys.exit(2)
    print("policy.yaml looks OK.")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv)>1 else "src/model_api/policy.yaml"
    main(p)
