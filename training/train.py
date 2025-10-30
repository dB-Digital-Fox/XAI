import os, glob, json
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

from src.common.utils import tolerant_load_file

OPENSTACK_ENABLED = os.getenv("OPENSTACK_ENABLED", "false").lower() == "true"
MODEL_PATH = os.getenv("MODEL_PATH", "./training/model.pkl")
PARTS_GLOB = os.getenv("PARTS_GLOB", "./data/parts/part_*.json")

def load_parts_local(glob_pat):
    paths = sorted(glob.glob(glob_pat))
    logs = []
    for p in paths:
        logs.extend(tolerant_load_file(p))
    return logs

def load_parts_openstack():
    from src.common.openstack_io import fetch_json_objects  # lazy import
    container = os.environ["OS_CONTAINER"]
    prefix = os.getenv("OS_PREFIX", "parts/")
    return fetch_json_objects(container, prefix)

def feature_row(alert):
    d = alert.get("data", {})
    r = alert.get("rule", {})
    return {
        "sentbyte": int(d.get("sentbyte", 0)),
        "rcvdbyte": int(d.get("rcvdbyte", 0)),
        "duration": int(d.get("duration", 0)),
        "rule_level": int(r.get("level", 0)),
        "apprisk_elevated": 1 if str(d.get("apprisk","")).lower() == "elevated" else 0,
        "hour": 0,
    }

def weak_label(alert):
    return 1 if int(alert.get("rule", {}).get("level", 0)) >= 10 else 0

def main():
    if OPENSTACK_ENABLED:
        try:
            logs = load_parts_openstack()
            if not logs:
                raise RuntimeError("No objects returned from OpenStack")
            print(f"[train] Loaded {len(logs)} alerts from OpenStack.")
        except Exception as e:
            print(f"[train] OpenStack unavailable ({e}); falling back to local files …")
            logs = load_parts_local(PARTS_GLOB)
    else:
        logs = load_parts_local(PARTS_GLOB)

    if not logs:
        raise SystemExit("[train] No training logs found. Check PARTS_GLOB or OpenStack paths.")

    rows = []
    for a in logs:
        row = feature_row(a)
        row["label"] = weak_label(a)
        rows.append(row)

    df = pd.DataFrame(rows)
    X = df.drop(columns=["label"])
    y = df["label"]

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(Xtr, ytr)

    print(classification_report(yte, model.predict(Xte)))
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[train] Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
