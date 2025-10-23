from __future__ import annotations
import os, json, math
from collections import Counter
from typing import Any, Dict, List, Tuple
from opensearchpy import OpenSearch

OS_URL  = os.environ.get("OS_URL", "https://localhost:9200")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "admin")
OS_TLS  = os.environ.get("OS_VERIFY_TLS", "true").lower()=="true"
INDEX   = os.environ.get("ALERT_INDEX", ".wazuh-alerts-*")
LIMIT   = int(os.environ.get("SAMPLE", "5000"))
MAX_DEPTH = 6

def is_num(v):
    return isinstance(v, (int, float)) and not (isinstance(v, float) and (math.isnan(v) or math.isinf(v)))

def flatten(obj: Any, prefix="") -> List[Tuple[str, Any]]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out += flatten(v, key)
            else:
                out.append((key, v))
    elif isinstance(obj, list):
        # heuristic: sample first element; also record array length feature
        if obj:
            out += flatten(obj[0], f"{prefix}[0]")
        out.append((f"{prefix}.len", len(obj)))
    return out

def sample_alerts() -> List[Dict]:
    client = OpenSearch(
        hosts=[OS_URL],
        http_auth=(OS_USER, OS_PASS),
        verify_certs=OS_TLS,
        ssl_assert_hostname=False, ssl_show_warn=False,
    )
    body = {"size": 1000, "query": {"match_all": {}}, "_source": True}
    resp = client.search(index=INDEX, body=body, scroll="2m")
    sid = resp.get("_scroll_id")
    total = 0
    docs = []
    while True:
        hits = resp["hits"]["hits"]
        if not hits: break
        for h in hits:
            docs.append(h.get("_source", {}))
            total += 1
            if total >= LIMIT: break
        if total >= LIMIT: break
        resp = client.scroll(scroll_id=sid, scroll="2m")
    return docs

def main():
    docs = sample_alerts()
    numeric_paths = Counter()
    cat_paths = Counter()

    for d in docs:
        for path, val in flatten(d):
            # ignore meta/time/id heavy fields
            if path.startswith("@timestamp") or path.endswith(".keyword"): 
                continue
            if is_num(val):
                numeric_paths[path] += 1
            elif isinstance(val, (str, bool)):
                cat_paths[path] += 1

    # choose frequent numeric fields
    min_support = max(5, int(0.02 * len(docs)))
    num_candidates = [p for p, c in numeric_paths.items() if c >= min_support and p.count(".") <= MAX_DEPTH]

    # recommend hashed versions for common categorical fields with low cardinality
    # (you can implement hashing upstream; here we just point them out)
    cat_candidates = [p for p, c in cat_paths.items() if c >= min_support and p.count(".") <= MAX_DEPTH]

    print("# Suggested numeric features for feature_map.yaml")
    print("features:")
    for p in sorted(num_candidates):
        name = p.replace("[0]", "_0").replace(".len", "_len").replace(".", "_")
        print(f"  - name: {name}")
        print(f"    path: {p}")
        print(f"    default: 0")

    if cat_candidates:
        print("\n# Consider hashing/one-hot upstream for these categorical fields:")
        for p in sorted(cat_candidates)[:40]:
            print(f"# - {p}")

if __name__ == "__main__":
    main()