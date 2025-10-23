from __future__ import annotations
import os, yaml, numpy as np
from opensearchpy import OpenSearch

OS_URL  = os.environ.get("OS_URL", "https://localhost:9200")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "admin")
OS_TLS  = os.environ.get("OS_VERIFY_TLS", "true").lower()=="true"
INDEX   = os.environ.get("ALERT_INDEX", ".wazuh-alerts-*")
FMAP    = os.environ.get("FEATURE_MAP_PATH", "src/model_api/feature_map.yaml")
N       = int(os.environ.get("N", "1000"))

def _get(d, dotted, default=None):
    cur = d
    for p in dotted.split("."):
        if p.endswith(".len"):
            arrpath = p[:-4]
            for q in arrpath.split("."):
                cur = cur.get(q, {})
            return len(cur) if isinstance(cur, list) else 0
        if isinstance(cur, dict) and p in cur: cur = cur[p]
        else: return default
    return cur

def main():
    fmap = yaml.safe_load(open(FMAP, "r", encoding="utf-8"))
    feats = fmap["features"]

    client = OpenSearch(
        hosts=[OS_URL],
        http_auth=(OS_USER, OS_PASS),
        verify_certs=OS_TLS, ssl_assert_hostname=False, ssl_show_warn=False
    )
    body = {"size": N, "query": {"match_all": {}}, "_source": True}
    hits = client.search(index=INDEX, body=body)["hits"]["hits"]

    coverage = {f["name"]: {"present":0, "total":len(hits)} for f in feats}
    for h in hits:
        src = h.get("_source", {})
        for f in feats:
            val = _get(src, f["path"], f.get("default", 0))
            if val != f.get("default", 0) and val is not None:
                coverage[f["name"]]["present"] += 1

    print("Coverage:")
    for k, v in coverage.items():
        pct = 100.0 * v["present"] / max(1, v["total"])
        print(f" - {k:24s}: {pct:5.1f}% ({v['present']}/{v['total']})")

if __name__ == "__main__":
    main()
