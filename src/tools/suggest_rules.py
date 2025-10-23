# src/tools/suggest_rules.py
from __future__ import annotations
import os, collections
from opensearchpy import OpenSearch

OS_URL  = os.environ.get("OS_URL","https://localhost:9200")
OS_USER = os.environ.get("OS_USER","admin")
OS_PASS = os.environ.get("OS_PASS","admin")
OS_TLS  = os.environ.get("OS_VERIFY_TLS","true").lower()=="true"
EXPLAIN_IDX = os.environ.get("EXPLAIN_INDEX","wazuh-explain-v1")
FEED_IDX    = os.environ.get("FEEDBACK_INDEX","wazuh-explain-feedback-v1")

CANDS = [
  ("win.event.code","num"),
  ("data.dstport","num"),
  ("enrich.auth_fail_5m","num"),
  ("enrich.user.risk","num"),
  ("data.geoip.src.risk_score","num"),
]

def fetch():
    cli = OpenSearch(hosts=[OS_URL], http_auth=(OS_USER,OS_PASS), verify_certs=OS_TLS, ssl_assert_hostname=False, ssl_show_warn=False)
    # join explain + feedback by alert_id (simple approach: two passes + dict join)
    ex = {}
    resp = cli.search(index=EXPLAIN_IDX, body={"size":10000,"query":{"match_all":{}},"_source":["alert_id","score","class_prob"]})
    for h in resp["hits"]["hits"]:
        s = h["_source"]; ex[s["alert_id"]] = s
    fb = {}
    resp = cli.search(index=FEED_IDX, body={"size":10000,"query":{"match_all":{}},"_source":["alert_id","trust_score","overridden"]})
    for h in resp["hits"]["hits"]:
        s = h["_source"]; fb[s["alert_id"]] = s

    # build labeled set
    joint = {}
    for aid, e in ex.items():
        if aid in fb:
            y = 1 if (int(fb[aid].get("trust_score",3))>=4 and not fb[aid].get("overridden", False)) else 0
            joint[aid] = (e, y)
    return joint

def get(d, path):
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur

def main():
    data = fetch()
    if not data:
        print("Not enough joined data.")
        return
    buckets = collections.defaultdict(lambda: collections.Counter())
    for _, (e, y) in data.items():
        alert = e.get("alert") or {}  # if you store raw alert; if not, skip
        for fld, typ in CANDS:
            v = get(alert, fld)
            if v is None: continue
            if typ == "num":
                # bin numerics
                try:
                    fv = float(v)
                    binv = int(fv//1) if fv < 20 else int(fv//5*5)
                    key = f"{fld} >= {binv}"
                except:
                    key = f"{fld} == {v}"
            else:
                key = f"{fld} == {v}"
            buckets[key][y] += 1

    print("# Suggested rules (precision shown as pos/(pos+neg))")
    for k, c in sorted(buckets.items(), key=lambda kv: -(kv[1][1]/max(1,(kv[1][1]+kv[1][0])))):
        pos, neg = c[1], c[0]
        if pos+neg < 30:  # support cutoff
            continue
        prec = pos/(pos+neg)
        if prec >= 0.85 and pos >= 20:  # good candidate
            print(f"- when: \"{k}\"    # precision ~{prec:.2f}, support {pos+neg}")
            print(f"  add_reason: \"Heuristic hit: {k}\"")
            print(f"  bump: 0.05\n")

if __name__ == "__main__":
    main()
