import argparse
import glob
import json
import os
import random
import statistics
from typing import Any, Dict, Iterable, List, Optional

import requests


# -----------------------------
# Input loaders (part*.json)
# -----------------------------
def tolerant_load_file(path: str) -> Any:
    """
    Loads:
      - JSON object
      - JSON array
      - JSON Lines (one JSON object per line)
    """
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
    """
    Tries common shapes:
      - list[alert]
      - {"alerts": [...]}, {"items": [...]}, {"data": [...]}
      - OpenSearch export: {"hits":{"hits":[{"_source":...}]}}
    """
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
        raise SystemExit(f"No alerts found in files matched by: {pattern}")

    return alerts


# -----------------------------
# Latency stats (your wrapper output)
# -----------------------------
def read_latencies_jsonl(path: str, *, only_success: bool = True) -> List[float]:
    """
    Reads your wrapper output file (JSONL) and extracts latency_ms.
    Expects each line to be a JSON dict with at least:
      - latency_ms: number
    Optionally:
      - status_code (filter to 200)
      - ok (filter to True)
    """
    if not os.path.exists(path):
        raise SystemExit(f"Latency file not found: {path}")

    lats: List[float] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            ms = rec.get("latency_ms")
            if not isinstance(ms, (int, float)):
                continue

            if only_success:
                # Accept common success signals
                code = rec.get("status_code")
                ok = rec.get("ok")
                if (code is not None and code != 200) or (ok is not None and ok is not True):
                    continue

            lats.append(float(ms))

    return lats


def percentile(values: List[float], p: float) -> float:
    """
    Nearest-rank percentile on sorted values.
    p in [0,100]
    """
    if not values:
        return float("nan")
    s = sorted(values)
    if p <= 0:
        return s[0]
    if p >= 100:
        return s[-1]
    idx = int(round((p / 100.0) * (len(s) - 1)))
    return s[idx]


# -----------------------------
# Sender
# -----------------------------
def post_explain(base_url: str, alert: Dict[str, Any], timeout_s: float) -> requests.Response:
    url = base_url.rstrip("/") + "/explain"
    return requests.post(url, json={"alert": alert}, timeout=timeout_s)


def main():
    ap = argparse.ArgumentParser(description="Send alerts from part*.json to /explain N times, then report median & p95 from existing latency.jsonl.")
    ap.add_argument("--base-url", default="http://localhost:8080", help="Backend base URL (default: http://localhost:8080)")
    ap.add_argument("--parts", required=True, help="Glob pattern for parts files, e.g. ./data/parts/part_*.json")
    ap.add_argument("--n", type=int, default=1000, help="How many requests to send (default: 1000)")
    ap.add_argument("--timeout", type=float, default=30.0, help="Request timeout seconds (default: 30)")
    ap.add_argument("--shuffle", action="store_true", help="Shuffle alerts before sending")
    ap.add_argument("--sample", action="store_true", help="Sample with replacement if fewer than N alerts available")
    ap.add_argument("--seed", type=int, default=1337, help="Random seed (default: 1337)")
    ap.add_argument("--latency-file", default="./data/outputs/latency.jsonl", help="Your wrapper output file (default: ./data/outputs/latency.jsonl)")
    ap.add_argument("--report-only", action="store_true", help="Do not send; only compute stats from latency file")
    ap.add_argument("--only-success", action="store_true", help="Only include successful requests in stats (status_code==200 or ok==true)")
    ap.add_argument("--clear-latency-file", action="store_true", help="Truncate latency file before sending (if you want clean run stats)")
    args = ap.parse_args()

    if args.clear_latency_file and not args.report_only:
        os.makedirs(os.path.dirname(args.latency_file) or ".", exist_ok=True)
        open(args.latency_file, "w", encoding="utf-8").close()
        print(f"[init] Cleared {args.latency_file}")

    if not args.report_only:
        alerts = load_alerts_from_glob(args.parts)
        rng = random.Random(args.seed)

        if args.shuffle:
            rng.shuffle(alerts)

        if args.n <= len(alerts):
            to_send = alerts[: args.n]
        else:
            if not args.sample:
                raise SystemExit(f"Only {len(alerts)} alerts available; use --sample to reach n={args.n}.")
            to_send = [alerts[rng.randrange(len(alerts))] for _ in range(args.n)]

        ok = 0
        fail = 0

        for i, alert in enumerate(to_send, start=1):
            try:
                r = post_explain(args.base_url, alert, args.timeout)
                if r.status_code == 200:
                    ok += 1
                else:
                    fail += 1
            except Exception:
                fail += 1

            if i % 50 == 0:
                print(f"[send] {i}/{args.n} ok={ok} fail={fail}")

        print(f"[send] done: ok={ok} fail={fail}")

    # Report stats from latency file (written by your wrapper)
    lats = read_latencies_jsonl(args.latency_file, only_success=args.only_success)

    if not lats:
        raise SystemExit(f"No latency samples found in {args.latency_file} (filters may be too strict).")

    med = statistics.median(lats)
    p95 = percentile(lats, 95)
    p99 = percentile(lats, 99)

    print("\n=== Latency summary (ms) ===")
    print(f"file:    {args.latency_file}")
    print(f"samples: {len(lats)}")
    print(f"median:  {med:.2f}")
    print(f"p95:     {p95:.2f}")
    print(f"p99:     {p99:.2f}")
    print(f"mean:    {statistics.mean(lats):.2f}")
    print(f"min:     {min(lats):.2f}")
    print(f"max:     {max(lats):.2f}")


if __name__ == "__main__":
    main()
