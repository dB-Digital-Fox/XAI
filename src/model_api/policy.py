from __future__ import annotations
import os, yaml, time, math
from typing import Any, Dict, List, Tuple

def _get(d: Dict, path: str, default=None):
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def _parse_when(expr: str):
    # very small, safe parser for expressions like "a.b >= 10", "x in [1,2]", "y == 1"
    expr = expr.strip()
    if " in " in expr:
        left, right = expr.split(" in ", 1)
        left = left.strip(); right = right.strip()
        if right.startswith("[") and right.endswith("]"):
            arr = [s.strip() for s in right[1:-1].split(",")]
            vals = []
            for v in arr:
                try: vals.append(float(v))  # numeric
                except: vals.append(v.strip("'\""))
            return ("in", left, vals)
    for op in [">=", "<=", "==", ">", "<"]:
        if op in expr:
            left, right = [s.strip() for s in expr.split(op, 1)]
            try:
                rnum = float(right)
                return (op, left, rnum)
            except:
                return (op, left, right.strip("'\""))
    return None

def _fmt_reason(tpl: str, alert: Dict):
    # interpolate #{a.b.c} tokens
    out, i = "", 0
    while i < len(tpl):
        if i+2 < len(tpl) and tpl[i] == "#" and tpl[i+1] == "{":
            j = tpl.find("}", i+2)
            if j != -1:
                path = tpl[i+2:j]
                val = _get(alert, path, "")
                out += str(val)
                i = j+1
                continue
        out += tpl[i]; i += 1
    return out

class Policy:
    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)
        self.th = self.cfg.get("thresholds", {})
        self.rules = self.cfg.get("rules", [])
        self.triage_text = self.cfg.get("triage_text", {})
        self.recs_by_tag = self.cfg.get("recommendations", {})

    def decide(self, score: float, alert: Dict, feature_used_mask: List[bool], feature_names: List[str], model_path: str):
        tag = "info"
        if score >= self.th.get("critical", 0.85): tag = "critical"
        elif score >= self.th.get("high", 0.70):   tag = "high"
        elif score >= self.th.get("medium", 0.50): tag = "medium"
        elif score >= self.th.get("low", 0.30):    tag = "low"

        bump = 0.0
        reasons: List[str] = []
        recs: List[str] = []

        for r in self.rules:
            spec = _parse_when(r.get("when",""))
            hit = False
            if spec:
                op, left, right = spec
                lv = _get(alert, left)
                try:
                    if op == "in":  hit = (lv in right)
                    elif op == "==": hit = (lv == right)
                    elif op == ">=": hit = (float(lv) >= float(right))
                    elif op == "<=": hit = (float(lv) <= float(right))
                    elif op == ">":  hit = (float(lv) >  float(right))
                    elif op == "<":  hit = (float(lv) <  float(right))
                except: hit = False
            if hit:
                if r.get("reason"): reasons.append(_fmt_reason(r["reason"], alert))
                if r.get("add_reason"): reasons.append(_fmt_reason(r["add_reason"], alert))
                if r.get("bump"): bump += float(r["bump"])
                if r.get("recommendations"): recs += r["recommendations"]
                if r.get("escalate_to"):
                    tag = r["escalate_to"]

        # after bumps, re-evaluate tag (without downgrades)
        boosted = max(0.0, min(1.0, score + bump))
        if boosted >= self.th.get("critical", 0.85): tag = "critical"
        elif boosted >= self.th.get("high", 0.70) and tag not in ("critical",): tag = "high"

        # add default reason
        reasons.insert(0, f"Score {boosted:.2f} ≥ {tag} threshold {self.th.get(tag, 0.0)}" if tag in self.th else f"Score {boosted:.2f}")

        # health/meta
        used = sum(1 for b in feature_used_mask if b)
        total = len(feature_used_mask) if feature_used_mask else 0
        cov = 100.0 * used / total if total else 0.0
        missing = [n for n, b in zip(feature_names, feature_used_mask) if not b]

        try:
            staleness_days = max(0, int((time.time() - os.path.getmtime(model_path)) / 86400))
        except Exception:
            staleness_days = None

        health = {
            "feature_coverage_pct": round(cov, 1),
            "missing_features": missing[:10],
            "model_staleness_days": staleness_days,
            "pipeline_ok": cov >= 60.0  # simple heuristic
        }

        triage = self.triage_text.get(tag, "")
        recs = list(dict.fromkeys(recs + self.recs_by_tag.get(tag, [])))  # dedupe, preserve order

        return {
            "criticality": {
                "tag": tag,
                "score": boosted,
                "reasons": reasons[:6],
                "triage_text": triage,
                "recommendations": recs[:6]
            },
            "health": health
        }
