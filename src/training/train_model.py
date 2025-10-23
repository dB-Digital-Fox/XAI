from __future__ import annotations
import os, json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier #Why RandomForest + calibration? It’s stable, SHAP-friendly (TreeExplainer), and quick to train. We can swap to XGBoost/LightGBM later for gains.
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, f1_score, precision_recall_fscore_support
from joblib import dump
from opensearchpy import OpenSearch
from feature_builder import FeatureBuilder

S_URL   = os.environ.get("OS_URL", "https://localhost:9200")
OS_USER  = os.environ.get("OS_USER", "admin")
OS_PASS  = os.environ.get("OS_PASS", "admin")
OS_TLS   = os.environ.get("OS_VERIFY_TLS", "true").lower() == "true"

ALERT_IDX   = os.environ.get("TRAIN_ALERT_INDEX", ".wazuh-alerts-*")
LABEL_FIELD = os.environ.get("LABEL_FIELD", "enrich.label")  # 1/0 or "malicious"/"benign"
FMAP_PATH   = os.environ.get("FEATURE_MAP_PATH", "src/model_api/feature_map.yaml")
OUT_PATH    = os.environ.get("MODEL_PATH_OUT", "src/model_api/model.joblib")

def fetch_labeled_alerts(limit=5000):
    """Pulls a sample of labeled alerts from OpenSearch. You can also export JSONL and skip this step."""
    client = OpenSearch(
        hosts=[OS_URL], http_auth=(OS_USER, OS_PASS), verify_certs=OS_TLS, ssl_assert_hostname=False, ssl_show_warn=False
    )
    body = {
        "size": 1000,
        "_source": ["@timestamp", "rule", "data", "enrich", "win", "message", LABEL_FIELD],
        "query": { "bool": { "must": [ { "exists": { "field": LABEL_FIELD } } ] } }
    }
    alerts = []
    resp = client.search(index=ALERT_IDX, body=body, scroll="2m")
    sid = resp.get("_scroll_id")
    total = 0
    while True:
        hits = resp["hits"]["hits"]
        if not hits: break
        for h in hits:
            src = h.get("_source", {})
            y = src
            alerts.append(src)
            total += 1
            if total >= limit: break
        if total >= limit: break
        resp = client.scroll(scroll_id=sid, scroll="2m")
    return alerts

def normalize_label(v):
    if v in (1, "1", True, "malicious", "anomaly", "alert"): return 1
    return 0

def main():
    fb = FeatureBuilder(FMAP_PATH)

    # Option A: from OpenSearch
    alerts = fetch_labeled_alerts()

    # Option B (offline): from JSONL file
    jsonl = os.environ.get("TRAIN_JSONL", "")
    if jsonl and os.path.exists(jsonl):
        alerts = [json.loads(line) for line in open(jsonl, "r", encoding="utf-8")]

    X_list, y_list = [], []
    for a in alerts:
        yv = a
        for part in LABEL_FIELD.split("."):
            if isinstance(yv, dict): yv = yv.get(part)
        if yv is None: continue
        X_list.append(fb.transform_one(a))
        y_list.append(normalize_label(yv))

    X = np.vstack(X_list)
    y = np.array(y_list)

    # Split, handle imbalance, and calibrate
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    base = RandomForestClassifier(
        n_estimators=400, max_depth=None, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=42
    )
    clf = CalibratedClassifierCV(base, method="isotonic", cv=3)
    clf.fit(Xtr, ytr)

    p = clf.predict_proba(Xte)[:,1]
    yhat = (p >= 0.5).astype(int)

    auc = roc_auc_score(yte, p)
    prec, rec, f1, _ = precision_recall_fscore_support(yte, yhat, average="binary")

    print(f"AUC={auc:.3f}  F1={f1:.3f}  P={prec:.3f}  R={rec:.3f}  N={len(yte)}")
    dump(clf, OUT_PATH)
    print(f"Saved model to {OUT_PATH}")

if __name__ == "__main__":
    main()
