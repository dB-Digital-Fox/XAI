# src/tools/suggest_thresholds.py
from __future__ import annotations
import os, numpy as np
from opensearchpy import OpenSearch

OS_URL  = os.environ.get("OS_URL","https://localhost:9200")
OS_USER = os.environ.get("OS_USER","admin")
OS_PASS = os.environ.get("OS_PASS","admin")
OS_TLS  = os.environ.get("OS_VERIFY_TLS","true").lower()=="true"
EXPLAIN_IDX = os.environ.get("EXPLAIN_INDEX","wazuh-explain-v1")
FEED_IDX    = os.environ.get("FEEDBACK_INDEX","wazuh-explain-feedback-v1")

def fetch_scored(n=20000):
    cli = OpenSearch(hosts=[OS_URL], http_auth=(OS_USER,OS_PASS), verify_certs=OS_TLS, ssl_assert_hostname=False, ssl_show_warn=False)
    body = {"size": 1000, "query": {"match_all": {}}, "_source": ["alert_id","score"]}
    out, resp = [], cli.search(index=EXPLAIN_IDX, body=body, scroll="2m")
    sid = resp.get("_scroll_id")
    while True:
        hits = resp["hits"]["hits"]
        if not hits: break
        for h in hits:
            s = h["_source"]
            out.append((s["alert_id"], float(s.get("score", 0.0))))
            if len(out) >= n: break
        if len(out) >= n: break
        resp = cli.scroll(scroll_id=sid, scroll="2m")
    return out

def fetch_labels():
    # Use analyst feedback: overridden=True ~ negative; high trust & not overridden ~ positive
    cli = OpenSearch(hosts=[OS_URL], http_auth=(OS_USER,OS_PASS), verify_certs=OS_TLS, ssl_assert_hostname=False, ssl_show_warn=False)
    body = {"size": 10000, "query": {"match_all": {}}, "_source": ["alert_id","trust_score","overridden"]}
    resp = cli.search(index=FEED_IDX, body=body)
    labels = {}
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        aid = s["alert_id"]
        # crude heuristic label from feedback
        y = 1 if (int(s.get("trust_score",3)) >= 4 and not s.get("overridden", False)) else 0
        labels[aid] = y
    return labels

def main():
    scores = fetch_scored()
    labels = fetch_labels()
    pairs = [(sc, labels.get(aid)) for aid, sc in scores if aid in labels]
    if not pairs:
        print("Not enough labeled data — set thresholds by policy."); return
    sc = np.array([p[0] for p in pairs], float)
    y  = np.array([p[1] for p in pairs], int)

    # choose cut points to meet target precisions
    for name, target_p in [("critical",0.95),("high",0.85),("medium",0.70),("low",0.50)]:
        best_t = 0.5; best_diff = 1e9
        for t in np.linspace(0.3, 0.99, 70):
            sel = sc >= t
            if sel.sum() == 0: continue
            prec = y[sel].mean() if sel.any() else 0
            diff = abs(prec - target_p)
            if diff < best_diff:
                best_diff, best_t = diff, t
        print(f"{name}: ~{best_t:.2f} (target precision {target_p*100:.0f}%)")

if __name__ == "__main__":
    main()
