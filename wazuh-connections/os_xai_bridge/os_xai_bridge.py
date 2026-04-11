#!/usr/bin/env python3
"""
Wazuh → OpenSearch → XAI Bridge
================================
Polls wazuh-alerts-* in OpenSearch for new documents,
forwards each one to the XAI backend at http://127.0.0.1:8080/explain,
and lets XAI index the enriched result into wazuh-explain-v2.

Flow:
  Wazuh ──► wazuh-alerts-* (OpenSearch, via Filebeat)
                └──► this poller picks up new docs
                          └──► POST to XAI :8080/explain
                                    └──► XAI enriches + indexes wazuh-explain-v2

Why this is better than the Wazuh integration:
  - Wazuh already indexed the raw alert first (A/B raw view works)
  - XAI gets the already-indexed doc with full OpenSearch metadata
  - Decoupled: XAI backend can be restarted without losing alerts
  - Resumable: tracks last processed timestamp in a state file

Usage:
  python3 os_xai_bridge.py                    # run with defaults
  python3 os_xai_bridge.py --interval 5       # poll every 5 seconds
  python3 os_xai_bridge.py --batch 50         # process 50 docs per poll
  python3 os_xai_bridge.py --reset            # clear state, reprocess all
  python3 os_xai_bridge.py --dry-run          # poll + print, don't call XAI
  python3 os_xai_bridge.py --since 2h         # reprocess last 2 hours
  python3 os_xai_bridge.py --since 30m        # reprocess last 30 minutes

Requirements:
  pip3 install requests urllib3
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── config ────────────────────────────────────────────────────────────────────

OPENSEARCH_URL   = "https://127.0.0.1:9200"
OPENSEARCH_INDEX = "wazuh-alerts-*"
OPENSEARCH_USER  = "admin"
OPENSEARCH_PASS  = "Eb9v7KHVsy5yPV+1YbtgbCg3.t2S*xYj"          # change to your actual password
OPENSEARCH_VERIFY_SSL = False       # set True + supply CA if in production

XAI_URL          = "http://127.0.0.1:8080/explain"
XAI_TIMEOUT      = 15              # seconds per request

STATE_FILE       = "/var/lib/wazuh-xai-bridge/state.json"
LOG_FILE         = "/var/log/wazuh-xai-bridge.log"

POLL_INTERVAL    = 10              # seconds between polls
BATCH_SIZE       = 100             # docs per poll cycle
MIN_RULE_LEVEL   = 0               # only forward alerts at this level or above

# ── logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("xai-bridge")


# ── state management ──────────────────────────────────────────────────────────

def load_state():
    path = Path(STATE_FILE)
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not read state file: {e}")
    return {"last_timestamp": None, "processed": 0, "errors": 0}


def save_state(state):
    path = Path(STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def reset_state():
    path = Path(STATE_FILE)
    if path.exists():
        path.unlink()
        log.info("State reset — will reprocess from beginning")


# ── opensearch helpers ────────────────────────────────────────────────────────

def os_request(method, path, body=None):
    url = f"{OPENSEARCH_URL}/{path}"
    kwargs = dict(
        auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify=OPENSEARCH_VERIFY_SSL,
        timeout=10,
        headers={"Content-Type": "application/json"},
    )
    if body:
        kwargs["json"] = body

    resp = getattr(requests, method)(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


def check_opensearch():
    try:
        info = os_request("get", "")
        version = info.get("version", {}).get("number", "unknown")
        log.info(f"OpenSearch connected — version {version}")
        return True
    except Exception as e:
        log.error(f"Cannot connect to OpenSearch at {OPENSEARCH_URL}: {e}")
        return False


def fetch_new_alerts(since_ts, batch_size):
    """
    Fetch alerts from wazuh-alerts-* newer than since_ts.
    Returns list of (index, doc_id, source) tuples, sorted by timestamp asc.
    """
    query = {
        "size": batch_size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": True,
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}}
                ]
            }
        }
    }

    if since_ts:
        query["query"]["bool"]["must"].append({
            "range": {
                "timestamp": {"gt": since_ts}
            }
        })
    else:
        # First run — only fetch last 1 hour to avoid flooding XAI
        one_hour_ago = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query["query"]["bool"]["must"].append({
            "range": {
                "timestamp": {"gte": one_hour_ago}
            }
        })

    try:
        result = os_request("post", f"{OPENSEARCH_INDEX}/_search", query)
        hits = result.get("hits", {}).get("hits", [])
        return [(h["_index"], h["_id"], h["_source"]) for h in hits]
    except Exception as e:
        log.error(f"OpenSearch query failed: {e}")
        return []



# ── xai forwarding ────────────────────────────────────────────────────────────

def _reconstruct_nested(source: dict, key: str, default: dict = None) -> dict:
    """
    Wazuh alerts in OpenSearch are stored in TWO possible formats
    depending on the Filebeat/index-template version:

      A) Nested  — source["rule"] = {"level": 5, "id": "2501", ...}
      B) Flat    — source["rule.level"] = 5, source["rule.id"] = "2501"

    This handles both transparently so build_payload always gets
    proper nested dicts regardless of how the doc was indexed.
    """
    if default is None:
        default = {}

    # Try native nested key first
    val = source.get(key)
    if isinstance(val, dict) and len(val) > 0:
        return val

    # Reconstruct from dot-notation flat keys
    built = {}
    prefix = key + "."
    for fk, fv in source.items():
        if fk.startswith(prefix):
            sub_key = fk[len(prefix):]
            # Only one level deep — deeper nesting (e.g. data.win.eventdata)
            # is rare in Wazuh alerts; handle if needed
            built[sub_key] = fv

    return built if built else default


def build_payload(index, doc_id, source):
    """
    Reconstruct a proper nested Wazuh alert from an OpenSearch document
    and wrap it under the "alert" key that XAI expects:

        { "alert": { "id": ..., "rule": {...}, "agent": {...}, "data": {...}, ... } }

    Handles both nested and flat (dot-notation) OpenSearch storage formats.
    Matches the exact structure used in the PowerShell evaluation scripts.
    """
    flat_keys = list(source.keys())

    rule       = _reconstruct_nested(source, "rule")
    agent      = _reconstruct_nested(source, "agent")
    manager    = _reconstruct_nested(source, "manager")
    data       = _reconstruct_nested(source, "data")
    decoder    = _reconstruct_nested(source, "decoder")
    predecoder = _reconstruct_nested(source, "predecoder")

    # rule.groups must always be a list
    if "groups" in rule:
        if isinstance(rule["groups"], str):
            rule["groups"] = [g.strip() for g in rule["groups"].split(",")]
        elif not isinstance(rule["groups"], list):
            rule["groups"] = list(rule["groups"])

    # rule.level must be int (some mappings store it as string)
    if "level" in rule:
        try:
            rule["level"] = int(rule["level"])
        except (ValueError, TypeError):
            pass

    alert = {
        "id":          source.get("id", doc_id),
        "timestamp":   source.get("timestamp") or source.get("@timestamp", ""),
        "rule":        rule,
        "agent":       agent,
        "manager":     manager,
        "data":        data,
        "decoder":     decoder,
        "predecoder":  predecoder,
        "location":    source.get("location", ""),
        "full_log":    source.get("full_log", ""),
        # Keep OS provenance so XAI can link enriched doc back to raw alert
        "_os_index":   index,
        "_os_doc_id":  doc_id,
    }

    # Strip keys with empty-dict or None values to keep payload clean
    alert = {k: v for k, v in alert.items() if v not in (None, {})}

    return {"alert": alert}


def forward_to_xai(index, doc_id, source, dry_run=False, debug=False):
    """POST the already-indexed Wazuh alert to the XAI backend."""
    payload   = build_payload(index, doc_id, source)
    rule_id   = source.get("rule", {}).get("id", "?")
    rule_level = source.get("rule", {}).get("level", "?")
    short_id  = doc_id[:20] + "…"

    if debug:
        print("\n" + "─" * 60)
        print(f"  DOC ID  : {doc_id}")
        print(f"  INDEX   : {index}")
        print(f"  RULE    : {rule_id}  level={rule_level}")
        print(f"  PAYLOAD :\n{json.dumps(payload, indent=2)}")
        print("─" * 60)

    if dry_run:
        log.info(f"  [DRY-RUN] rule={rule_id} level={rule_level} doc={short_id}")
        return True

    try:
        resp = requests.post(
            XAI_URL,
            json=payload,
            timeout=XAI_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )

        if debug:
            print(f"  RESPONSE STATUS : {resp.status_code}")
            print(f"  RESPONSE BODY   :\n{resp.text}")
            print("─" * 60 + "\n")

        if resp.status_code in (200, 201, 202, 204):
            log.info(f"  ✓ rule={rule_id} level={rule_level} doc={short_id} → {resp.status_code}")
            return True
        else:
            log.warning(
                f"  ✗ XAI {resp.status_code} for doc={short_id}\n"
                f"    rule={rule_id} level={rule_level}\n"
                f"    response: {resp.text[:600]}"
            )
            return False

    except requests.exceptions.Timeout:
        log.warning(f"  ✗ XAI timeout  doc={short_id}")
        return False
    except Exception as e:
        log.error(f"  ✗ XAI request failed  doc={short_id}: {e}")
        return False


# ── poll loop ─────────────────────────────────────────────────────────────────

def poll_once(state, batch_size, dry_run=False, debug=False):
    since = state.get("last_timestamp")
    alerts = fetch_new_alerts(since, batch_size)

    if not alerts:
        return 0, 0

    log.info(f"Fetched {len(alerts)} new alert(s) from {OPENSEARCH_INDEX}")

    ok = 0
    err = 0
    last_ts = since

    for index, doc_id, source in alerts:
        success = forward_to_xai(index, doc_id, source, dry_run=dry_run, debug=debug)
        if success:
            ok += 1
        else:
            err += 1

        # Track the latest timestamp we've processed
        doc_ts = source.get("timestamp")
        if doc_ts and (last_ts is None or doc_ts > last_ts):
            last_ts = doc_ts

    # Save progress — even if some failed, advance the cursor
    # so we don't retry the same batch forever
    if last_ts and last_ts != since:
        state["last_timestamp"] = last_ts

    state["processed"] = state.get("processed", 0) + ok
    state["errors"]    = state.get("errors", 0) + err

    if not dry_run:
        save_state(state)

    return ok, err


# ── main ──────────────────────────────────────────────────────────────────────

def parse_since(since_str):
    """Parse --since argument like '2h', '30m', '1d' into an ISO timestamp."""
    if not since_str:
        return None
    unit  = since_str[-1]
    value = int(since_str[:-1])
    delta = {
        "m": timedelta(minutes=value),
        "h": timedelta(hours=value),
        "d": timedelta(days=value),
    }.get(unit)
    if not delta:
        log.error(f"Invalid --since format '{since_str}'. Use e.g. 30m, 2h, 1d")
        sys.exit(1)
    ts = datetime.now(timezone.utc) - delta
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def main():
    parser = argparse.ArgumentParser(
        description="Poll OpenSearch wazuh-alerts-* and forward to XAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--interval", type=float, default=POLL_INTERVAL,
                        help=f"Poll interval in seconds (default: {POLL_INTERVAL})")
    parser.add_argument("--batch",    type=int,   default=BATCH_SIZE,
                        help=f"Docs per poll cycle (default: {BATCH_SIZE})")
    parser.add_argument("--reset",    action="store_true",
                        help="Clear saved state and reprocess from last hour")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Poll and log but do not call XAI")
    parser.add_argument("--since",    type=str, default=None,
                        help="Reprocess alerts from this time back (e.g. 2h, 30m, 1d)")
    parser.add_argument("--once",     action="store_true",
                        help="Run a single poll cycle and exit")
    parser.add_argument("--debug",    action="store_true",
                        help="Print full payload and XAI response for every doc")
    parser.add_argument("--probe",    action="store_true",
                        help="Send only the single most recent alert to XAI and exit")
    parser.add_argument("--watch",    action="store_true",
                        help="Tail Wazuh alert stream after bridge stops")
    args = parser.parse_args()

    print(f"""
{'='*60}
  Wazuh → OpenSearch → XAI Bridge
  OpenSearch : {OPENSEARCH_URL}/{OPENSEARCH_INDEX}
  XAI        : {XAI_URL}
  Interval   : {args.interval}s
  Batch size : {args.batch}
  Dry-run    : {args.dry_run}
  Min level  : {MIN_RULE_LEVEL}
{'='*60}
""")

    if args.reset:
        reset_state()

    if not check_opensearch():
        sys.exit(1)

    state = load_state()

    # Override starting timestamp if --since supplied
    if args.since:
        state["last_timestamp"] = parse_since(args.since)
        log.info(f"Reprocessing from {state['last_timestamp']}")

    # ── probe mode: send one doc and show full exchange ────────────────
    if args.probe:
        log.info("PROBE MODE — fetching most recent alert and sending to XAI")
        alerts = fetch_new_alerts(None, 1)
        if not alerts:
            log.error("No alerts found in wazuh-alerts-*")
            sys.exit(1)
        index, doc_id, source = alerts[0]
        forward_to_xai(index, doc_id, source, dry_run=False, debug=True)
        sys.exit(0)

    log.info(f"Starting — last processed timestamp: {state.get('last_timestamp', 'none (last 1h)')}")
    log.info(f"Total processed so far: {state.get('processed', 0)}")

    try:
        while True:
            ok, err = poll_once(state, args.batch, dry_run=args.dry_run, debug=args.debug)
            if ok or err:
                log.info(f"Poll complete — sent: {ok}  errors: {err}  "
                         f"total: {state['processed']}")
            if args.once:
                break
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n")
        log.info(f"Stopped. Total processed: {state.get('processed',0)}  "
                 f"errors: {state.get('errors',0)}")
        log.info(f"State saved to {STATE_FILE}")


if __name__ == "__main__":
    main()