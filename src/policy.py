# src/policy.py
from __future__ import annotations
import os, json
from typing import Any, Dict, Tuple

try:
    import yaml
except Exception:
    yaml = None

POLICY_PATH = os.getenv("POLICY_MAP_PATH", "./config/policy_map.yaml")

def _load_yaml_or_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    if path.endswith((".yaml", ".yml")):
        if yaml is None:
            raise RuntimeError("PyYAML not installed but YAML policy provided.")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_policy() -> Dict[str, Any]:
    return _load_yaml_or_json(POLICY_PATH)

def match_overrides(when: Dict[str, Any], canon: Dict[str, Any]) -> bool:
    # Support simple equality and numeric comparisons in strings (">=2", "<=1")
    for k, v in when.items():
        cv = canon.get(k)
        if isinstance(v, str) and (v.startswith(">=") or v.startswith("<=") or v.startswith(">") or v.startswith("<")):
            try:
                tgt = float(v.replace(">=","").replace("<=","").replace(">","").replace("<",""))
                cur = float(cv or 0)
                if v.startswith(">=") and not (cur >= tgt): return False
                if v.startswith("<=") and not (cur <= tgt): return False
                if v.startswith(">")  and not (cur >  tgt): return False
                if v.startswith("<")  and not (cur <  tgt): return False
            except Exception:
                return False
        else:
            if cv != v:
                return False
    return True

def apply_policy(policy: Dict[str, Any], score: float, source: str, canon: Dict[str, Any]) -> Dict[str, Any]:
    pdefs   = policy.get("defaults", {})
    sources = policy.get("sources", {})
    srcpol  = sources.get(source, {})
    bands   = srcpol.get("bands", [])

    # decision threshold
    threshold = float(srcpol.get("decision_threshold", pdefs.get("decision_threshold", 0.5)))

    # initial tag from bands
    tag = srcpol.get("default_tag", pdefs.get("default_tag", "LOW"))
    action = pdefs.get("min_action", "Queue")
    recommend = pdefs.get("min_recommendation", "Monitor traffic")
    for band in sorted(bands, key=lambda b: float(b.get("min", 0)), reverse=True):
        if score >= float(band.get("min", 0)):
            tag = band.get("tag", tag)
            action = band.get("action", action)
            recommend = band.get("recommend", recommend)
            break

    # overrides
    for ov in policy.get("overrides", []) or []:
        when = ov.get("when", {})
        if match_overrides(when, canon):
            if "elevate_to" in ov:
                tag = ov["elevate_to"]
            if "downgrade_to" in ov:
                tag = ov["downgrade_to"]

    # SHAP/show options
    shap_enabled   = bool(pdefs.get("shap_enabled", True))
    shap_min_score = float(pdefs.get("shap_min_score", 0.2))
    top_k_min      = int(pdefs.get("top_k_min", 10))
    top_k          = int(pdefs.get("top_k", 12))

    do_shap = shap_enabled and (score >= shap_min_score)
    eff_top_k = max(top_k_min, top_k)

    return {
        "threshold": threshold,
        "tag": tag,
        "action": action,
        "recommendation": recommend,
        "do_shap": do_shap,
        "top_k": eff_top_k,
    }
