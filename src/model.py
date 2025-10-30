import os, joblib
import numpy as np
import shap

class Explainer:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None
        else:
            self.explainer = None

    def predict_proba(self, x: np.ndarray) -> float:
        if self.model is None:
            # fallback dummy
            return 0.5
        return float(self.model.predict_proba(x.reshape(1, -1))[0, 1])

    def explain(self, alert: dict, feats: dict) -> dict:
        names = list(feats.keys())
        x = np.array([feats[k] for k in names], dtype=float)
        score = self.predict_proba(x)

        top = []
        if self.explainer is not None and self.model is not None:
            try:
                vals = self.explainer.shap_values(x.reshape(1, -1))
                # For binary RF in shap, vals may be list [neg, pos]
                phi = vals[1][0] if isinstance(vals, list) else vals[0]
                # Top by absolute impact
                order = np.argsort(-np.abs(phi))[:5]
                for idx in order:
                    top.append({"feature": names[idx], "value": float(x[idx]), "impact": float(phi[idx])})
            except Exception:
                pass

        label = "malicious" if score >= 0.5 else "benign"
        reason = "Top impact: " + ", ".join([t["feature"] for t in top]) if top else "Model score only"
        recommendation = "Investigate" if label == "malicious" else "Monitor traffic"

        return {
            "model_version": "v0.1",
            "predicted_score": score,
            "predicted_label": label,
            "top_features": top,
            "reason": reason,
            "recommendation": recommendation,
            "timestamp": alert.get("@timestamp") or alert.get("timestamp")
        }
