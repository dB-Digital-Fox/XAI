# training/train.py
#weighted grey-positives + OpenStack→local fallback + calibrated RF + SHAP k-means background
from __future__ import annotations
from shap.plots._labels import labels
import os, sys, glob, json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

# Ensure we can import src.* when running as a script or module
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Aligned feature extractor + tolerant loader (array JSON or JSONL)
try:
    from src.features import extract_features
    from src.common.utils import tolerant_load_file
except Exception as e:
    print("[train] Import error:", e)
    raise

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report
from sklearn.metrics import average_precision_score, precision_recall_curve
from src.features import extract_features, get_feature_names

# load the feature map form features.py
from src.features import get_feature_names

# -------- ENV / paths --------
OPENSTACK_ENABLED = os.getenv("OPENSTACK_ENABLED", "false").lower() == "true"
MODEL_PATH        = os.getenv("MODEL_PATH", "./training/model.pkl")
PARTS_GLOB        = os.getenv("PARTS_GLOB", "./data/parts/part_*.json")
SHAP_BG_PATH      = "./training/shap_bg.npy"
FEAT_NAMES_PATH   = "./training/feature_names.json"
SHAP_BG_K         = int(os.getenv("SHAP_BG_K", "60"))   # speed/fidelity knob (≈30–100)

# -------- Data loaders --------
def load_parts_local(glob_pat: str) -> list[dict]:
    paths = sorted(glob.glob(glob_pat))
    logs: list[dict] = []
    for p in paths:
        logs.extend(tolerant_load_file(p))
    return logs

def load_parts_openstack() -> list[dict]:
    from src.common.openstack_io import fetch_json_objects  # lazy import
    container = os.environ["OS_CONTAINER"]
    prefix    = os.getenv("OS_PREFIX", "parts/")
    return fetch_json_objects(container, prefix)

# -------- Weak signals & weighted labels (Option B) --------
def _to_int(x, default=0):
    try:
        return int(str(x))
    except Exception:
        return default

def weak_signals(alert: dict) -> float:
    """
    Produce a crude 0..1 'weak risk' score from interpretable signals.
    Tune weights/thresholds as needed for your data.
    """
    d = alert.get("data", {}) or {}
    r = alert.get("rule", {}) or {}

    lvl      = _to_int(r.get("level"), 0)
    sev      = (d.get("severity") or "").lower()
    apprisk  = (d.get("apprisk") or "").lower()
    dstport  = _to_int(d.get("dstport"), 0)
    sent     = _to_int(d.get("sentbyte"), 0)
    rcvd     = _to_int(d.get("rcvdbyte"), 0)
    dur      = _to_int(d.get("duration"), 0)
    action   = (d.get("action") or "").lower()
    subtype  = (d.get("subtype") or "").lower()

    bytes_total = sent + rcvd
    sensitive_ports = {22, 3389, 5985, 5986, 445}

    score = 0.0
    # rule level
    if lvl >= 12: score += 0.35
    elif lvl >= 8: score += 0.20
    elif lvl >= 6: score += 0.08
    # severity / app risk
    if sev == "critical": score += 0.35
    elif sev == "high":  score += 0.25
    elif sev == "medium":score += 0.10
    if apprisk in {"high", "elevated"}: score += 0.20
    # services/ports
    if dstport in sensitive_ports:
        score += 0.15
        if action != "dropped":
            score += 0.10
    # volume / time
    if bytes_total > 5_000_000: score += 0.25
    elif bytes_total > 1_000_000: score += 0.10
    if dur > 7200: score += 0.20
    elif dur > 1800: score += 0.10
    # IPS categories
    if subtype in {"malware"}: score += 0.30
    elif subtype in {"ips", "ids"}: score += 0.08

    return min(score, 1.0)

def weak_label_and_weight(alert: dict, low: float = 0.15, high: float = 0.35, grey_weight: float = 0.35) -> tuple[int, float]:
    """
    - risk >= high      → strong positive (label=1, weight=1.0)
    - risk <= low       → clear negative (label=0, weight=1.0)
    - low < risk < high → grey-positive (label=1, weight=grey_weight)
    """
    r = weak_signals(alert)
    if r >= high:
        return 1, 1.0
    if r <= low:
        return 0, 1.0
    return 1, float(grey_weight)

# -------- Main training --------
def main():


    # 1) Load alerts (OpenStack → local fallback)
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
        raise SystemExit("[train] No training logs found. Check PARTS_GLOB or OpenStack settings.")

    # 2) Build feature rows + labels + sample weights
    rows: list[dict] = []
    labels: list[int] = []
    weights: list[float] = []

    n_bad = 0
    for a in logs:
        try:
            feats = extract_features(a)            # map-aware
            y, w = weak_label_and_weight(a)        # Option B
            # enforce int/bool labels safely
            y = int(1 if y else 0)
            w = float(w)
            rows.append(feats)
            labels.append(y)
            weights.append(w)
        except Exception as e:
            n_bad += 1

    if not rows:
        raise SystemExit(f"[train] No usable rows (bad={n_bad}). Check PARTS_GLOB/OpenStack and weak labels.")

    df = pd.DataFrame(rows)
    feature_names = get_feature_names()

    # Ensure all expected columns exist; add missing as zeros
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0.0

    # Strict schema: keep only expected features and in the expected order
    df = df[feature_names].copy()

    # Attach labels (must match length)
    if len(labels) != len(df):
        raise SystemExit(f"[train] Label length mismatch: labels={len(labels)} df={len(df)} (bad=   {n_bad})")

    df["label"] = labels

    # Remove any NaNs defensively (should not happen)
    before = len(df)
    df = df.dropna(subset=["label"])
    after = len(df)
    if after < before:
        print(f"[train] Dropped {before - after} rows with NaN labels.")

    # Final matrices
    y = df["label"].astype(int).values
    X = df.drop(columns=["label"]).astype(float).values
    sw = np.array(weights, dtype=float)

    # Sanity assertions
    assert X.shape[0] == y.shape[0] == sw.shape[0], f"len mismatch X={X.shape} y={y.shape} sw={sw.  shape}"
    assert X.shape[1] == len(feature_names), f"width mismatch X={X.shape[1]} vs names={len  (feature_names)}"

    # Diagnostics to understand current balance
    classes, counts = np.unique(y, return_counts=True)
    print("[train] Class distribution:", dict(zip(classes.tolist(), counts.tolist())))
    print(f"[train] Positive rate: {float((y==1).mean()):.3f}")
    if len(classes) < 2:
        raise SystemExit("[train] Only one class present. Adjust weak_label_and_weight thresholds or    add more data.")

    # 4) Split (train/val/test) with stratification; keep weights in sync
    X_tr, X_tmp, y_tr, y_tmp, sw_tr, sw_tmp = train_test_split(
        X, y, sw, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_te, y_val, y_te, sw_val, sw_te = train_test_split(
        X_tmp, y_tmp, sw_tmp, test_size=0.50, random_state=42, stratify=y_tmp
    )

    # 5) Train balanced RF with sample_weight; then calibrate (prefit) on validation set
    base = RandomForestClassifier(
        n_estimators=600,
        max_depth=6,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",  # balanced_subsample - handle any residual imbalance
        min_samples_leaf=80, #SOC data is noisy; larger leaves help
        # class_weight=None  # we provide per-sample weights
    )
    base.fit(X_tr, y_tr, sample_weight=sw_tr)

    cal = CalibratedClassifierCV(base, method="sigmoid", cv="prefit") # can replace isotonic with the sigmoid method Sigmoid is smoother and safer with limited data. Isotonic can fit better but overfits with small calibration sets.
    cal.fit(X_val, y_val)  # calibration; sklearn doesn't accept weights here

    proba = cal.predict_proba(X_te)[:,1]
    ap = average_precision_score(y_te, proba)
    print("[eval] AUPRC (Average Precision):", ap)

    # Choose threshold by top-K rate (e.g., flag top 1% as suspicious)
    thr = np.quantile(proba, 0.99)
    y_hat = (proba >= thr).astype(int)
    print("[eval] Threshold (top 1%):", thr)
    print(classification_report(y_te, y_hat, digits=3, zero_division=0))

    print(classification_report(y_te, cal.predict(X_te)))
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(cal, MODEL_PATH)
    print(f"[train] Model saved to {MODEL_PATH}")

    # 6) Save SHAP background summary (k-means prototypes) for fast Kernel SHAP at inference
    try:
        import shap
        bg_pool = X_tr  # could also stack X_tr + X_val for a bit more coverage
        K = max(10, SHAP_BG_K)
        summary = shap.kmeans(bg_pool, K)   # returns Dataset-like; use .data ndarray
        np.save(SHAP_BG_PATH, summary.data)
        print(f"[train] Saved SHAP k-means background (K={K}) to {SHAP_BG_PATH}")
    except Exception as e:
        print(f"[train] SHAP background summarization skipped: {e}")

    # 7) Persist feature order for the API explainer
    try:
        with open(FEAT_NAMES_PATH, "w", encoding="utf-8") as f:
            json.dump(feature_names, f)
        print(f"[train] Saved feature names to {FEAT_NAMES_PATH}")
    except Exception as e:
        print(f"[train] Failed to save feature names: {e}")

if __name__ == "__main__":
    main()
