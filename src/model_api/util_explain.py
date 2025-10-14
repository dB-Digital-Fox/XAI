from __future__ import annotations
import numpy as np, pandas as pf, shap, json, os, yaml
from lime.lime_tabular import LimeTabularExplainer
from joblib import load as joblib_load

def _get(d: dict, dotted: str, default=None):
    cur = d
    for p in dotted.split('.'):
        if not instance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

class Explainer:
    def __init__(self, model_path: str, feature_map_path: str, backend: str = "shap", top_k: int = 8):
        self.model = joblib_load(model_path)
        self.backend = backend
        self.top_k = top_k
        with open(feature_map_path, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        self.feature_defs = spec["features"]
        self.feature_names = [f["name"] for f in self.feature_defs]

        #for LIME baseline ranges
        self._means = np.zeros(len(self.feature_names))
        self._stds = np.ones(len(self.feature_names))

        #prefit SHAP
        if backend == "shap":
            try:
                self.shap_explainer = shap.Explainer(self.model)
            except Exception:
                self.shap_explainer = shap.KernelExplainer(self.model.predict_proba, shap.kmeans(np.zeros((10,len(self.feature_names))), 5))

    def xform(self, alert: dict) -> np.ndarray:
        vals = []
        for f in self.feature_defs:
            vals.append(_get(alert, f["path"], f.get("default",0)))
        return np.array(vals, dtype = float)
    
    def predict_proba(self, X: np.ndarray):
         # 2-class assumption; adjust if needed
        return self.model.predict_proba(X.reshape(1, -1))[0].tolist()
    
    def explain(self, alert: dict) -> dict:
        X = self.xform(alert)
        proba = self.predict_proba(X)
        score = float(proba[1])  #assume binary classification, adjust if needed

        if self.backend == "shap":
            sv = self.shap_explainer(X.reshape(1,-1))
            phi = sv.values[0]
            base_val = float(sv.base_values[0]) if hasattr(sv.base_values, "__len__") else 0.0
            contribs = list(zip(self.feature_names, phi))
        else:
            expl = LimeTabularExplainer(
                training_data = np.stack([self._means]*50) + np.random.randn(50, len(self._means))*self._stds,
                feature_names = self.feature_names,
                mode = "classification"
            )
            exp = expl.explain_instance(X, lambda z: self.model.predict_proba(z), num_features=min(self.top_k, len(self.feature_names)))
            contribs = exp.as_list()
            base_val = None

        #sort absolute impact
        contrib_sorted = sorted(contribs, key=lambda x: abs(float(x[1])), reverse=True)[:self.top_k]
        top_features = [{"feature": f, "contribution": float(v)} for f,v in contrib_sorted]

        #optional: extract decisive events back from alert
        decisice = []
        if "evidence" in alert:
            for ev in alert["evidence"][:5]:
                decisive.append({
                    "ts": ev.get("@timestamp"),
                    "type": ev.get("kind") or ev.get("rule", {}).get("description"),
                    "snippet": ev.get("message", "")[:240]
                })

        return {
            "model": os.path.basename(os.environ.get("MODEL_PATH","model.joblib")),
            "backend": self.backend,
            "score": score,
            "class_prob": {"neg": float(proba[0]), "pos": float(proba[1])},
            "top_features": top_features,
            "base_value": base_val,
            "decisive_events": decisive
        }