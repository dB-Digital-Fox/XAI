import argparse
import glob
import json
import math
import os
import random
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


# -----------------------------
# Load alerts from part*.json
# -----------------------------
def tolerant_load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read().strip()
    if not txt:
        return []
    try:
        return json.loads(txt)
    except Exception:
        pass

    out = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def iter_alerts(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, list):
        for a in obj:
            if isinstance(a, dict):
                yield a
        return

    if isinstance(obj, dict):
        for k in ("alerts", "items", "data"):
            v = obj.get(k)
            if isinstance(v, list):
                for a in v:
                    if isinstance(a, dict):
                        yield a
                return

        hits = obj.get("hits", {}).get("hits")
        if isinstance(hits, list):
            for h in hits:
                if isinstance(h, dict) and isinstance(h.get("_source"), dict):
                    yield h["_source"]
            return


def load_alerts_from_glob(pattern: str) -> List[Dict[str, Any]]:
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise SystemExit(f"No files matched: {pattern}")

    alerts: List[Dict[str, Any]] = []
    for p in paths:
        obj = tolerant_load_file(p)
        alerts.extend(list(iter_alerts(obj)))

    if not alerts:
        raise SystemExit("No alerts found in provided parts files.")
    return alerts


# -----------------------------
# Explain API call + extraction
# -----------------------------
def post_explain(base_url: str, alert: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/explain"
    r = requests.post(url, json={"alert": alert}, timeout=timeout_s)
    try:
        js = r.json()
    except Exception:
        js = {"raw_text": r.text[:2000]}
    js["_http_status"] = r.status_code
    return js


def extract_explanation(resp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes response into:
      { score: float|None, label: str|None, top_features: list[dict], reason: str|None }
    Supports both:
      - {"ok": true, "explanation": {...}}
      - flat dict with predicted_score/predicted_label/top_features
      - nested model/policy/explanation style
    """
    if not isinstance(resp, dict):
        return {"score": None, "label": None, "top_features": [], "reason": None}

    exp = resp.get("explanation")
    if isinstance(exp, dict):
        core = exp
    else:
        core = resp

    # score
    score = None
    for path in (
        ("predicted_score",),
        ("model", "score"),
        ("score",),
    ):
        cur = core
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok:
            try:
                score = float(cur)
                break
            except Exception:
                pass

    # label
    label = None
    for path in (
        ("predicted_label",),
        ("model", "label"),
        ("label",),
    ):
        cur = core
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and cur is not None:
            label = str(cur)
            break

    # top_features array
    top = []
    for candidate in ("top_features",):
        if isinstance(core, dict) and isinstance(core.get(candidate), list):
            top = core[candidate]
            break
    # nested: core["explanation"]["top_features"] if present
    if not top and isinstance(core, dict) and isinstance(core.get("explanation"), dict):
        tf = core["explanation"].get("top_features")
        if isinstance(tf, list):
            top = tf

    # reason
    reason = None
    if isinstance(core, dict):
        reason = core.get("reason") or (core.get("explanation", {}) or {}).get("reason")

    # sanitize top_features
    clean = []
    if isinstance(top, list):
        for t in top:
            if not isinstance(t, dict):
                continue
            feat = t.get("feature")
            if feat is None:
                continue
            clean.append({
                "feature": str(feat),
                "value": t.get("value"),
                "impact": t.get("impact"),
            })

    return {"score": score, "label": label, "top_features": clean, "reason": reason}


# -----------------------------
# Metrics
# -----------------------------
def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def spearman_rank_corr(xs: List[float], ys: List[float]) -> Optional[float]:
    """
    Spearman correlation for two equal-length lists.
    Returns None if not enough points.
    """
    n = len(xs)
    if n < 2:
        return None

    def ranks(vs: List[float]) -> List[float]:
        # average ranks for ties
        sorted_idx = sorted(range(n), key=lambda i: vs[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and vs[sorted_idx[j + 1]] == vs[sorted_idx[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[sorted_idx[k]] = avg
            i = j + 1
        return r

    rx = ranks(xs)
    ry = ranks(ys)
    mx = sum(rx) / n
    my = sum(ry) / n
    num = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    denx = math.sqrt(sum((rx[i] - mx) ** 2 for i in range(n)))
    deny = math.sqrt(sum((ry[i] - my) ** 2 for i in range(n)))
    if denx == 0 or deny == 0:
        return None
    return num / (denx * deny)


def mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else float("nan")


def stdev(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Repeat same alerts multiple times and measure explanation consistency.")
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--parts", required=True, help="Glob for part files, e.g. ./data/parts/part_*.json")
    ap.add_argument("--k", type=int, default=100, help="How many unique alerts to test (default 100)")
    ap.add_argument("--rounds", type=int, default=10, help="How many repeats of the same set (default 10)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--random-pick", action="store_true", help="Randomly pick K alerts (otherwise first K)")
    ap.add_argument("--out", default="./data/outputs/consistency_responses.jsonl")
    ap.add_argument("--fail-fast", action="store_true", help="Stop on first non-200 response")
    args = ap.parse_args()

    alerts = load_alerts_from_glob(args.parts)
    rng = random.Random(args.seed)

    if args.random_pick:
        if len(alerts) < args.k:
            raise SystemExit(f"Need at least {args.k} alerts, got {len(alerts)}")
        picks = rng.sample(alerts, args.k)
    else:
        picks = alerts[: args.k]
        if len(picks) < args.k:
            raise SystemExit(f"Need at least {args.k} alerts, got {len(picks)}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        pass  # truncate

    # Per-item tracking by stable key: doc_id if present else index position
    def key_for_alert(a: Dict[str, Any], idx: int) -> str:
        return str(a.get("id") or a.get("doc_id") or (a.get("alert", {}) or {}).get("id") or f"idx_{idx}")

    per = defaultdict(lambda: {"scores": [], "labels": [], "feat_sets": [], "impacts": []})

    total = args.k * args.rounds
    sent = 0

    for r in range(args.rounds):
        for i, alert in enumerate(picks):
            sent += 1
            k = key_for_alert(alert, i)

            resp = post_explain(args.base_url, alert, args.timeout)
            status = resp.get("_http_status")

            if args.fail_fast and status != 200:
                raise SystemExit(f"Non-200 response at round={r+1} i={i+1}: status={status} body={resp}")

            exp = extract_explanation(resp)

            # write raw record
            rec = {
                "round": r + 1,
                "i": i + 1,
                "key": k,
                "http_status": status,
                "score": exp["score"],
                "label": exp["label"],
                "top_features": exp["top_features"],
                "reason": exp["reason"],
            }
            with open(args.out, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

            # aggregate
            if exp["score"] is not None:
                per[k]["scores"].append(exp["score"])
            per[k]["labels"].append(exp["label"])

            fs = set(t["feature"] for t in exp["top_features"] if isinstance(t, dict) and t.get("feature"))
            per[k]["feat_sets"].append(fs)

            # store impacts by feature (for rank corr)
            imp = {}
            for t in exp["top_features"]:
                if not isinstance(t, dict):
                    continue
                feat = t.get("feature")
                if feat is None:
                    continue
                try:
                    imp[str(feat)] = float(t.get("impact"))
                except Exception:
                    continue
            per[k]["impacts"].append(imp)

            if sent % 50 == 0:
                print(f"[send] {sent}/{total}")

    # -----------------------------
    # Consistency report
    # -----------------------------
    rows = []
    for k, d in per.items():
        scores = d["scores"]
        labels = d["labels"]
        feat_sets = d["feat_sets"]
        impacts = d["impacts"]

        # label flips
        uniq_labels = set(labels)
        flip_rate = 0.0
        if len(labels) > 1:
            flips = sum(1 for j in range(1, len(labels)) if labels[j] != labels[j - 1])
            flip_rate = flips / (len(labels) - 1)

        # score stability
        s_std = stdev(scores) if scores else float("nan")
        s_delta = (max(scores) - min(scores)) if scores else float("nan")

        # feature set stability: mean Jaccard vs first round
        jac = []
        if feat_sets:
            base = feat_sets[0]
            for fs in feat_sets[1:]:
                jac.append(jaccard(base, fs))
        jac_mean = mean(jac) if jac else 1.0

        # impact rank stability: Spearman vs first round on shared features
        rho = []
        if impacts:
            base = impacts[0]
            for cur in impacts[1:]:
                shared = sorted(set(base.keys()) & set(cur.keys()))
                if len(shared) < 2:
                    continue
                xs = [base[f] for f in shared]
                ys = [cur[f] for f in shared]
                r = spearman_rank_corr(xs, ys)
                if r is not None:
                    rho.append(r)
        rho_mean = mean(rho) if rho else float("nan")

        rows.append({
            "key": k,
            "rounds": args.rounds,
            "label_set": sorted(list(uniq_labels)),
            "label_flip_rate": flip_rate,
            "score_std": s_std,
            "score_max_delta": s_delta,
            "topfeat_jaccard_mean_vs_r1": jac_mean,
            "impact_spearman_mean_vs_r1": rho_mean
        })

    # global summary
    flip_rates = [r["label_flip_rate"] for r in rows]
    jacs = [r["topfeat_jaccard_mean_vs_r1"] for r in rows]
    score_stds = [r["score_std"] for r in rows if not math.isnan(r["score_std"])]

    print("\n=== Consistency summary ===")
    print(f"alerts tested: {len(rows)}  rounds: {args.rounds}")
    print(f"label flip rate (mean): {mean(flip_rates):.4f}")
    print(f"top-features Jaccard vs round1 (mean): {mean(jacs):.4f}")
    print(f"score stddev (mean): {mean(score_stds):.6f}")

    # show worst offenders (top 10 by flip rate, then low jaccard)
    rows_sorted = sorted(rows, key=lambda r: (-r["label_flip_rate"], r["topfeat_jaccard_mean_vs_r1"]))
    print("\nWorst 10 (by label flips, then low Jaccard):")
    for r in rows_sorted[:10]:
        print(
            f"- {r['key']}: flip_rate={r['label_flip_rate']:.3f} "
            f"jaccard={r['topfeat_jaccard_mean_vs_r1']:.3f} "
            f"score_std={r['score_std'] if not math.isnan(r['score_std']) else 'nan'} "
            f"labels={r['label_set']}"
        )

    # save summary as JSON
    summary_path = os.path.splitext(args.out)[0] + "_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"\nSaved detailed per-alert summary to: {summary_path}")
    print(f"Saved raw responses JSONL to:         {args.out}")


if __name__ == "__main__":
    main()