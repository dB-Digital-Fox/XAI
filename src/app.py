import os, time
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from dotenv import load_dotenv
import numpy as np
from .model import Explainer
from .features import extract_features
from .storage import StorageManager
from .feedback import FeedbackManager

load_dotenv(".env.app")

MODE = os.getenv("STORAGE_MODE", "local")  # "local" or "opensearch"

app = FastAPI(title="Explainable SOC Backend (Minimal)")

explainer = Explainer(model_path="./training/model.pkl")
storage = StorageManager(mode=MODE)
feedback_mgr = FeedbackManager(mode=MODE)

class ExplainIn(BaseModel):
    alert: Dict[str, Any]

class FeedbackIn(BaseModel):
    alert_id: str
    trust_score: int  # 1..5
    overridden: bool
    decision_ms: int

# ------------------------------
# API
# ------------------------------

@app.post("/explain")
def explain(
    body: ExplainIn,
    top_k: Optional[int] = Query(default=None, ge=1, le=50, description="Top features to return"),
):
    alert = body.alert
    try:
        # 1) Build numeric features
        feats = extract_features(alert)
        
        # 2) Get explanation from model (includes policy application)
        exp = explainer.explain(alert, feats, top_k_override=top_k)
        
        # 3) Post-process: unique ID and persistence
        doc_id = str(alert.get("id") or int(time.time() * 1000))
        storage.store_explanation({"doc_id": doc_id, **exp})
        return {"ok": True, 
                "alert": alert,
                "raw": alert,
                "explanation": {"doc_id": doc_id,"raw": alert, **exp}}
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        raise HTTPException(400, f"explain error: {e}")

    try:
        # 1) Build numeric features (map-aware) and model vector
        feats = extract_features(alert)
        names, x = explainer._feature_array(feats)  # preserves saved order
        n_feats = len(names)

        # 2) Score first (cheap), then apply policy (to decide SHAP budget)
        score = explainer.predict_proba(x)
        source = _infer_source(alert)
        # Use the same dictionary for policy conditions (policy can refer to any numeric feature names)
        canon_for_policy = {**feats}
        decision = apply_policy(POLICY, score, source, canon_for_policy)

        # 3) Decide how many features to show (respect query param but clamp safely)
        k = _clamp_top_k(
            k_req=top_k if top_k is not None else decision.get("top_k", 10),
            n_feats=n_feats,
            min_floor=decision.get("top_k", 10),  # use policy's top_k as floor
            default_k=decision.get("top_k", 10)
        )
        
        # 4) Build explanation with policy-aware cost control
        top = []
        reason = "Model score only"
        # Try Tree SHAP first
        phi = None
        try:
            phi = explainer._shap_tree(x)
        except Exception:
            phi = None

        # If SHAP allowed by policy and tree failed, try Kernel SHAP
        if phi is None and decision.get("do_shap", True):
            try:
                phi = explainer._shap_kernel(x)
            except Exception:
                phi = None

        if phi is not None:
            phi = np.array(phi, dtype=float).reshape(-1)
            order = np.argsort(-np.abs(phi)).astype(int)
            valid = order[order < n_feats]
            top = explainer._append_nonzero_features(valid, names, x, phi, k)
            if top:
                reason = "Top impact: " + ", ".join([t["feature"] for t in top])
        else:
            # Fallback to feature_importances_
            base_est = getattr(explainer.model, "base_estimator_", explainer.model)
            if hasattr(base_est, "feature_importances_"):
                fi = np.array(base_est.feature_importances_, dtype=float).reshape(-1)
                order = np.argsort(-fi).astype(int)
                valid = order[order < n_feats]
                top = explainer._append_nonzero_features(valid, names, x, fi, k)
                if top:
                    reason = "Top impact (FI): " + ", ".join([t["feature"] for t in top])

        # 5) Label + recommendation (policy + heuristic)
        label = "malicious" if score >= float(decision.get("threshold", 0.5)) else "benign"
        recommendation = decision.get("recommendation") or ("Investigate" if label == "malicious" else "Monitor traffic")

        # 6) Build enriched response (alert first, then findings)
        # Filter features to hide those with value 0.0 as requested
        filtered_feats = {k: v for k, v in feats.items() if v != 0.0}

        return {
            "alert": alert,            # raw Wazuh log at the beginning
            "ok": True,
            "features": filtered_feats, # numeric features (non-zero only)
            "findings": {
                "model": {
                    "version": "v0.2",
                    "score": score,
                    "label": label,
                },
                "policy": {
                    "source": source,
                    "threshold": float(decision.get("threshold", 0.5)),
                    "tag": decision.get("tag", "LOW"),
                    "action": decision.get("action", "Queue"),
                    "recommendation": recommendation,
                    "do_shap": bool(decision.get("do_shap", True)),
                    "top_k_effective": k
                },
                "explanation": {
                    "top_features": top,
                    "reason": reason
                }
            }
        }

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        raise HTTPException(400, f"explain error: {e}")

@app.post("/feedback")
def feedback(body: FeedbackIn):
    try:
        feedback_mgr.store_feedback(body.model_dump())
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, f"feedback error: {e}")

@app.get("/metrics")
def metrics():
    return feedback_mgr.metrics()
