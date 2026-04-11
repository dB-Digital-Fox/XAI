#!/usr/bin/env python3
"""
Wazuh alerts.json → XAI Bridge
================================
Tails /var/ossec/logs/alerts/alerts.json directly — the native Wazuh
JSON output — and forwards each alert to XAI as { "alert": <wazuh_doc> }.

Why this beats the OpenSearch bridge:
  - Zero reconstruction:  fields are already perfectly nested
      rule: { level, id, description, groups }
      data: { srcip, dstip, severity, action, ... }
      agent, decoder, manager — all proper nested dicts
  - No Filebeat flattening / dot-notation issues
  - No SSL / auth config needed
  - Zero latency — fires the moment Wazuh writes the alert
  - Works even if OpenSearch is down

Flow:
  Wazuh alert
    ├──► /var/ossec/logs/alerts/alerts.json   ← this bridge reads here
    │         └──► POST { "alert": <doc> } → XAI :8080/explain
    │                   └──► XAI enriches → indexes wazuh-explain-v2
    └──► Filebeat → wazuh-alerts-* (OpenSearch)  ← Discover / A/B raw view

Usage:
  sudo python3 alerts_xai_bridge.py                  # tail live, forward all
  sudo python3 alerts_xai_bridge.py --min-level 3    # only level >= 3
  sudo python3 alerts_xai_bridge.py --dry-run        # print, don't POST
  sudo python3 alerts_xai_bridge.py --backfill 500   # replay last N lines first
  sudo python3 alerts_xai_bridge.py --debug          # print full payload + response
  sudo python3 alerts_xai_bridge.py --filter ssh     # only alerts matching keyword

Requirements:
  pip3 install requests
  Must be run as root (or wazuh group) to read /var/ossec/logs/alerts/alerts.json
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── config ────────────────────────────────────────────────────────────────────

ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
XAI_URL      = "http://127.0.0.1:8080/explain"
XAI_TIMEOUT  = 15
MIN_LEVEL    = 6          # forward alerts at this rule.level or above
STATE_FILE   = "/var/lib/wazuh-xai-bridge/alerts_state.json"

# ── logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("alerts-bridge")


# ── state ─────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"byte_offset": 0, "sent": 0, "errors": 0}


def save_state(state: dict):
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── payload ───────────────────────────────────────────────────────────────────

def build_payload(alert: dict) -> dict:
    """
    Wazuh native JSON already has perfectly nested fields:
      { "rule": {"level": 5, "id": "2501", "groups": [...] },
        "agent": {"id": "000", "name": "db-wazuh"},
        "data":  {"srcip": "...", "severity": "high", ...},
        "full_log": "...",
        ... }

    XAI expects: { "alert": <wazuh_doc> }
    That's it — no reconstruction needed.
    """
    return {"alert": alert}


# ── filtering ─────────────────────────────────────────────────────────────────

def passes_filter(alert: dict, min_level: int, keyword: str = None) -> bool:
    level = 0
    try:
        level = int((alert.get("rule") or {}).get("level", 0))
    except (ValueError, TypeError):
        pass

    if level < min_level:
        return False

    if keyword:
        kw = keyword.lower()
        haystack = json.dumps(alert).lower()
        if kw not in haystack:
            return False

    return True


# ── xai post ─────────────────────────────────────────────────────────────────

def post_to_xai(alert: dict, dry_run: bool = False, debug: bool = False) -> bool:
    payload  = build_payload(alert)
    rule     = alert.get("rule") or {}
    rule_id  = rule.get("id", "?")
    level    = rule.get("level", "?")
    desc     = rule.get("description", "")[:60]
    agent    = (alert.get("agent") or {}).get("name", "?")
    ts       = alert.get("timestamp", "")[:19]

    if debug:
        print("\n" + "─" * 65)
        print(f"  timestamp : {ts}")
        print(f"  rule      : {rule_id}  level={level}  {desc}")
        print(f"  agent     : {agent}")
        # Show the key nested fields to confirm structure
        print(f"  data      : {json.dumps(alert.get('data', {}), separators=(',',':'))}")
        print(f"  decoder   : {json.dumps(alert.get('decoder', {}), separators=(',',':'))}")
        print(f"  groups    : {rule.get('groups', [])}")
        print(f"  full_log  : {str(alert.get('full_log',''))[:80]}")
        print(f"  payload   :\n{json.dumps(payload, indent=2)[:800]}")
        print("─" * 65)

    if dry_run:
        log.info(f"  [DRY-RUN] rule={rule_id} level={level} agent={agent}  {desc}")
        return True

    try:
        resp = requests.post(
            XAI_URL,
            json=payload,
            timeout=XAI_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )

        if debug:
            print(f"  → XAI {resp.status_code}  {resp.text[:300]}")
            print("─" * 65 + "\n")

        if resp.status_code in (200, 201, 202, 204):
            log.info(f"  ✓ rule={rule_id} level={level} agent={agent}  {desc}")
            return True
        else:
            log.warning(
                f"  ✗ XAI {resp.status_code}  rule={rule_id} level={level}\n"
                f"    {resp.text[:400]}"
            )
            return False

    except requests.exceptions.Timeout:
        log.warning(f"  ✗ timeout  rule={rule_id}")
        return False
    except Exception as e:
        log.error(f"  ✗ request failed  rule={rule_id}: {e}")
        return False


# ── file tailer ───────────────────────────────────────────────────────────────

def iter_new_lines(f, poll_interval: float = 0.5):
    """
    Generator that yields new complete lines from an open file handle,
    blocking between polls. Handles log rotation (file shrinks → reopen).
    """
    while True:
        line = f.readline()
        if line:
            yield line.rstrip("\n")
        else:
            time.sleep(poll_interval)
            # Detect rotation: current file size < our position
            try:
                size = os.path.getsize(ALERTS_FILE)
                if size < f.tell():
                    log.info("Log rotation detected — reopening alerts.json")
                    return   # caller will reopen
            except OSError:
                pass


def backfill(path: str, n_lines: int, min_level: int, keyword: str,
             dry_run: bool, debug: bool) -> tuple[int, int]:
    """Read the last N lines of alerts.json and forward them."""
    log.info(f"Backfilling last {n_lines} lines from {path} …")
    try:
        # Read last N lines efficiently with a deque
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            last = deque(f, maxlen=n_lines)
    except OSError as e:
        log.error(f"Cannot open {path}: {e}")
        return 0, 0

    ok = err = 0
    for raw in last:
        raw = raw.strip()
        if not raw:
            continue
        try:
            alert = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not passes_filter(alert, min_level, keyword):
            continue
        if post_to_xai(alert, dry_run=dry_run, debug=debug):
            ok += 1
        else:
            err += 1
        time.sleep(0.05)   # don't flood XAI

    log.info(f"Backfill done — sent: {ok}  errors: {err}")
    return ok, err


# ── main loop ─────────────────────────────────────────────────────────────────

def tail_and_forward(args, state: dict):
    path = Path(ALERTS_FILE)

    while True:
        if not path.exists():
            log.warning(f"{ALERTS_FILE} not found — waiting …")
            time.sleep(5)
            continue

        log.info(f"Opening {ALERTS_FILE} at byte offset {state['byte_offset']}")

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                # Resume from last known position (survives restarts)
                try:
                    f.seek(state["byte_offset"])
                except OSError:
                    f.seek(0, 2)   # go to end if offset invalid

                for raw in iter_new_lines(f, poll_interval=0.3):
                    raw = raw.strip()
                    if not raw:
                        continue

                    try:
                        alert = json.loads(raw)
                    except json.JSONDecodeError as e:
                        log.debug(f"Skipping non-JSON line: {e}")
                        continue

                    if not passes_filter(alert, args.min_level, args.filter):
                        state["byte_offset"] = f.tell()
                        continue

                    if post_to_xai(alert, dry_run=args.dry_run, debug=args.debug):
                        state["sent"] += 1
                    else:
                        state["errors"] += 1

                    state["byte_offset"] = f.tell()

                    if not args.dry_run:
                        save_state(state)

        except OSError as e:
            log.error(f"File read error: {e} — retrying in 5s")
            time.sleep(5)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Tail Wazuh alerts.json and forward native alerts to XAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--min-level", type=int, default=MIN_LEVEL,
                        help=f"Minimum rule.level to forward (default: {MIN_LEVEL})")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Parse and filter but do not POST to XAI")
    parser.add_argument("--debug",     action="store_true",
                        help="Print full payload and XAI response for every alert")
    parser.add_argument("--backfill",  type=int, default=0, metavar="N",
                        help="Replay last N lines before starting live tail")
    parser.add_argument("--filter",    type=str, default=None, metavar="KEYWORD",
                        help="Only forward alerts whose JSON contains this keyword")
    parser.add_argument("--reset",     action="store_true",
                        help="Clear saved byte offset (start from end of file)")
    parser.add_argument("--from-start", action="store_true",
                        help="Start from the beginning of the file (reprocess all)")
    args = parser.parse_args()

    print(f"""
{'='*60}
  Wazuh alerts.json → XAI Bridge
  Source  : {ALERTS_FILE}
  XAI     : {XAI_URL}
  Level   : >= {args.min_level}
  Dry-run : {args.dry_run}
  Debug   : {args.debug}
  Filter  : {args.filter or 'none'}
{'='*60}
""")

    # Check file access
    if not os.path.exists(ALERTS_FILE):
        log.error(f"{ALERTS_FILE} does not exist.")
        log.error("Is Wazuh manager running? Check: systemctl status wazuh-manager")
        log.error("Is jsonout_output=yes in ossec.conf?")
        sys.exit(1)

    if not os.access(ALERTS_FILE, os.R_OK):
        log.error(f"Cannot read {ALERTS_FILE} — run with sudo or add user to wazuh group:")
        log.error("  sudo usermod -aG wazuh $USER")
        sys.exit(1)

    state = load_state()

    if args.reset:
        state["byte_offset"] = 0
        log.info("State reset — starting from end of file")
        # Jump to end
        state["byte_offset"] = os.path.getsize(ALERTS_FILE)

    if args.from_start:
        state["byte_offset"] = 0
        log.info("Starting from beginning of file")

    log.info(f"Total previously sent: {state['sent']}  errors: {state['errors']}")

    # Optional backfill before going live
    if args.backfill > 0:
        ok, err = backfill(
            ALERTS_FILE, args.backfill,
            args.min_level, args.filter,
            args.dry_run, args.debug
        )
        state["sent"]   += ok
        state["errors"] += err
        if not args.dry_run:
            save_state(state)

    log.info("Starting live tail …")
    try:
        tail_and_forward(args, state)
    except KeyboardInterrupt:
        print()
        log.info(f"Stopped.  Total sent: {state['sent']}  errors: {state['errors']}")
        if not args.dry_run:
            save_state(state)


if __name__ == "__main__":
    main()