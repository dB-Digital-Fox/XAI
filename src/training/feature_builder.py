from __future__ import annotations
import yaml, numpy as np
from typing import Dict, Any, List

def _get(d: Dict[str, Any], dotted: str, default=None):
    cur = d
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

class FeatureBuilder:
    def __init__(self, feature_map_path: str):
        with open(feature_map_path, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        self.feature_defs: List[Dict[str, Any]] = spec["features"]
        self.feature_names = [f["name"] for f in self.feature_defs]

    def transform_one(self, alert: Dict[str, Any]) -> np.ndarray:
        vals = []
        for f in self.feature_defs:
            vals.append(_get(alert, f["path"], f.get("default", 0)))
        # Optional: include a template_id if present (from Drain3)
        templ = _get(alert, "enrich.template_id", None)
        if templ is not None and "template_id" not in self.feature_names:
            # Add on-the-fly as numeric hash; or predefine in feature_map
            vals.append(abs(hash(str(templ))) % 100000)
        return np.array(vals, dtype=float)

    def names(self) -> List[str]:
        n = list(self.feature_names)
        # reflect optional template_id
        if "template_id" not in n:
            n.append("template_id")  # harmless if not used
        return n
