import os, json, joblib
import numpy as np
import shap
from .policy import load_policy, apply_policy

FEAT_NAMES_PATH = "./training/feature_names.json"
SHAP_BG_PATH = "./training/shap_bg.npy"

# Desired default number of features to show; we also enforce a minimum floor of 10 when enough features exist.
TOP_K_DEFAULT = int(os.getenv("TOP_K", "10"))
TOP_K_MIN_FLOOR = int(os.getenv("TOP_K_MIN", "10"))  # minimum when n_feats >= 10

class Explainer:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = joblib.load(model_path) if os.path.exists(model_path) else None

        # Load persisted feature order (keeps train/serve aligned)
        self.feature_names = None
        if os.path.exists(FEAT_NAMES_PATH):
            try:
                with open(FEAT_NAMES_PATH, "r", encoding="utf-8") as f:
                    self.feature_names = json.load(f)
            except Exception:
                self.feature_names = None

        # Prefer TreeExplainer when possible (faster, exact for trees)
        self.tree_explainer = None
        try:
            base = getattr(self.model, "base_estimator_", None) or getattr(self.model, "estimator", None) or self.model
            self.tree_explainer = shap.TreeExplainer(base)
        except Exception:
            self.tree_explainer = None

        # Kernel background (summarized via k-means in training)
        self.kernel_explainer = None
        self.shap_bg = None
        if os.path.exists(SHAP_BG_PATH):
            try:
                bg = np.load(SHAP_BG_PATH)
                bg = np.array(bg, dtype=float)
                if bg.ndim == 1:
                    bg = bg.reshape(1, -1)
                self.shap_bg = bg
            except Exception:
                self.shap_bg = None

        # Load policy
        self.policy = load_policy()

    def _infer_source(self, alert: dict) -> str:
        dec = (alert.get("decoder", {}) or {}).get("name", "").lower()
        groups = [g.lower() for g in (alert.get("rule", {}) or {}).get("groups", []) or []]
        agent  = (alert.get("agent", {}) or {}).get("name", "").lower()
        full   = " ".join([dec, " ".join(groups), agent])
        if any(k in full for k in ["fortigate", "cisco", "unifi", "asa", "firewall", "router", "switch"]):
            return "network"
        if "windows" in full or "win" in dec or "win" in agent or alert.get("win", {}).get("event"):
            return "endpoint"
        if "linux" in full:
            return "endpoint"
        if any(k in full for k in ["openstack", "nova", "keystone", "neutron"]):
            return "server"
        # Fall back by fields
        d = (alert.get("data", {}) or {})
        if d.get("devid") or d.get("subtype") == "ips":
            return "network"
        return "server"

    def _feature_array(self, feats: dict):
        # Stable order across runs; fall back to dict order if no saved list
        names = self.feature_names if self.feature_names is not None else list(feats.keys())
        x = np.array([float(feats.get(k, 0.0)) for k in names], dtype=float)
        return names, x

    def predict_proba(self, x1d: np.ndarray) -> float:
        if self.model is None:
            return 0.5
        proba = self.model.predict_proba(x1d.reshape(1, -1))[0, 1]
        return float(proba)

    def _shap_tree(self, x1d: np.ndarray):
        if self.tree_explainer is None:
            raise RuntimeError("no tree explainer")
        vals = self.tree_explainer.shap_values(x1d.reshape(1, -1))
        # binary -> list [neg, pos]; multiclass -> array; unify to 1D array
        if isinstance(vals, list):
            arr = np.array(vals[-1][0], dtype=float)  # positive class
        else:
            arr = np.array(vals[0], dtype=float)
        return arr.reshape(-1)

    def _shap_kernel(self, x1d: np.ndarray):
        if self.shap_bg is None:
            raise RuntimeError("no kernel background")
        if self.kernel_explainer is None:
            self.kernel_explainer = shap.KernelExplainer(
                lambda X: self.model.predict_proba(X)[:, 1],
                self.shap_bg
            )
        sv = self.kernel_explainer.shap_values(x1d.reshape(1, -1))
        # KernelExplainer returns array shape (1, n_features)
        arr = np.array(sv, dtype=float)
        if arr.ndim == 2 and arr.shape[0] == 1:
            arr = arr[0]
        return arr.reshape(-1)

    @staticmethod
    def _clamp_top_k(k_req: int | None, n_feats: int) -> int:
        """
        If n_feats >= 10: show at least max(TOP_K_MIN_FLOOR, TOP_K_DEFAULT, k_req) but not more than n_feats.
        If n_feats < 10: show all n_feats.
        """
        # derive base desired K
        try:
            base = TOP_K_DEFAULT if k_req is None else int(k_req)
        except Exception:
            base = TOP_K_DEFAULT
        base = max(1, base)

        if n_feats >= 10:
            k = max(base, TOP_K_MIN_FLOOR)
            return min(k, n_feats)
        else:
            return n_feats

    def _append_nonzero_features(
        self,
        order: np.ndarray,
        names: list[str],
        x: np.ndarray,
        impacts: np.ndarray,
        k_limit: int
    ) -> list[dict]:
        out = []
        kept = 0
        for idx in order:
            idx = int(idx)
            val = float(x[idx])
            imp = float(impacts[idx])
            # User requested: ignores the features where the values are 0.0 or 1.0
            if val == 0.0:
                continue
            out.append({"feature": names[idx], "value": val, "impact": imp})
            kept += 1
            if kept >= k_limit:
                break
        return out

    def explain(self, alert: dict, feats: dict, top_k_override: int = None) -> dict:
        names, x = self._feature_array(feats)
        n_feats = len(names)
        score = self.predict_proba(x)

        # Policy application
        source = self._infer_source(alert)
        decision = apply_policy(self.policy, score, source, feats)
        
        # Decide K
        k = self._clamp_top_k(
            top_k_override if top_k_override is not None else decision.get("top_k", 10), 
            n_feats
        )

        top = []
        phi = None

        if self.model is not None:
            # 1) Try Tree SHAP
            try:
                print("tree shap")
                phi = self._shap_tree(x)
            except Exception:
                phi = None

            # 2) Fallback to Kernel SHAP (only if allowed by policy)
            if phi is None and decision.get("do_shap", True):
                try:
                    print("kernel shap")
                    phi = self._shap_kernel(x)
                except Exception:
                    phi = None

            # 3) Feature importances fallback (if no SHAP)
            if phi is None:
                print("feature importances")
                base_est = getattr(self.model, "base_estimator_", self.model)
                if hasattr(base_est, "feature_importances_"):
                    fi = np.array(base_est.feature_importances_, dtype=float).reshape(-1)
                    order = np.argsort(-fi).astype(int)

                    # keep only indices that exist in current vector
                    valid = order[order < n_feats]
                    top = self._append_nonzero_features(valid, names, x, fi, k)

        # If we do have SHAP values, rank by |impact| and clamp K again safely
        if phi is not None:
            phi = np.array(phi, dtype=float).reshape(-1)
            order = np.argsort(-np.abs(phi)).astype(int)
            order = order[order < n_feats]
            top = self._append_nonzero_features(order, names, x, phi, k)

        label = "malicious" if score >= float(decision.get("threshold", 0.5)) else "benign"
        reason = "Top impact: " + ", ".join([t["feature"] for t in top]) if top else "Model score only"
        recommendation = decision.get("recommendation") or ("Investigate" if label == "malicious" else "Monitor traffic")

        # Filter features to hide 0.0 and 1.0 values
        filtered_feats = {k: v for k, v in feats.items() if v != 0.0}

        return {
            "alert": alert,
            "model_version": "v0.2",
            "predicted_score": score,
            "predicted_label": label,
            "top_features": top,
            "features": filtered_feats,
            "reason": reason,
            "recommendation": recommendation,
            "timestamp": alert.get("@timestamp") or alert.get("timestamp")
        }
