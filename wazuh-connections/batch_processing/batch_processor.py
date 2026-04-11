#!/usr/bin/env python3
"""
Wazuh Scheduled Batch Processor
=================================
Runs every N minutes (via cron or systemd timer).
Reads /var/ossec/logs/alerts/alerts.json for the current time window,
dumps matching alerts to a JSON batch file, then POSTs each to XAI.

Why batch over tail:
  - No long-running process to crash or get stuck
  - Clean audit trail — every batch file is preserved
  - Failed batches are retried automatically next run
  - Time window is exact and auditable
  - Works even if XAI was down — dump exists, retry later

Directory layout:
  /var/lib/xai-batches/
    pending/    ← batch files waiting to be processed
    done/       ← successfully processed batches
    failed/     ← batches where XAI returned errors (retried next run)
    state.json  ← last processed timestamp

Usage:
  # Run manually
  sudo python3 batch_processor.py

  # Dry run — dump batch file but don't POST to XAI
  sudo python3 batch_processor.py --dry-run

  # Dump only — write batch file, skip XAI entirely
  sudo python3 batch_processor.py --dump-only

  # Custom window (override the 10min default)
  sudo python3 batch_processor.py --window 60

  # Replay a specific failed batch file
  sudo python3 batch_processor.py --replay /var/lib/xai-batches/failed/batch_XYZ.json

  # Retry all failed batches
  sudo python3 batch_processor.py --retry-failed

  # Reset state (reprocess last N minutes)
  sudo python3 batch_processor.py --reset --window 120

Cron (every 10 minutes):
  */10 * * * * root /usr/bin/python3 /opt/wazuh-xai-bridge/batch_processor.py >> /var/log/xai-batch.log 2>&1

Systemd timer: see batch-processor.timer / batch-processor.service
"""

import argparse
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ── config ────────────────────────────────────────────────────────────────────

ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
XAI_URL      = "http://127.0.0.1:8080/explain"
XAI_TIMEOUT  = 15

BATCH_DIR    = Path("/var/lib/xai-batches")
PENDING_DIR  = BATCH_DIR / "pending"
DONE_DIR     = BATCH_DIR / "done"
FAILED_DIR   = BATCH_DIR / "failed"
STATE_FILE   = BATCH_DIR / "state.json"

WINDOW_MIN   = 10       # default time window in minutes
MIN_LEVEL    = 1        # minimum rule.level to include

# ── logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("xai-batch")


# ── dirs + state ──────────────────────────────────────────────────────────────

def ensure_dirs():
    for d in (PENDING_DIR, DONE_DIR, FAILED_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"last_ts": None, "batches_sent": 0, "alerts_sent": 0, "errors": 0}


def save_state(state: dict):
    BATCH_DIR.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── time window ───────────────────────────────────────────────────────────────

def parse_alert_ts(alert: dict):
    """Parse Wazuh timestamp into a UTC-aware datetime. Returns None on failure."""
    raw = alert.get("timestamp") or alert.get("@timestamp") or ""
    if not raw:
        return None
    # Wazuh format: 2026-03-20T13:25:19.819+0100
    # Try multiple formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ):
        try:
            return datetime.strptime(raw[:29], fmt[:len(fmt)])
        except Exception:
            pass
    try:
        # Python 3.7+ fromisoformat handles +0100 style
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def window_bounds(window_min: int, last_ts_iso: str = None):
    """
    Returns (start_dt, end_dt) as UTC-aware datetimes.
    - end   = now
    - start = last processed timestamp if available, else now - window_min
    """
    end = datetime.now(timezone.utc)
    if last_ts_iso:
        try:
            start = datetime.fromisoformat(last_ts_iso)
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            # Safety: never go back more than 4x the window to avoid huge batches
            earliest = end - timedelta(minutes=window_min * 4)
            start = max(start, earliest)
            return start, end
        except Exception:
            pass
    return end - timedelta(minutes=window_min), end


# ── alert reader ──────────────────────────────────────────────────────────────

def read_window(start_dt: datetime, end_dt: datetime, min_level: int) -> list[dict]:
    """
    Scan alerts.json and return all alerts whose timestamp falls in [start, end].
    Native Wazuh JSON — perfectly nested, no reconstruction needed.
    """
    if not os.path.exists(ALERTS_FILE):
        log.error(f"{ALERTS_FILE} not found — is Wazuh manager running?")
        return []

    if not os.access(ALERTS_FILE, os.R_OK):
        log.error(f"Cannot read {ALERTS_FILE} — run as root or add user to wazuh group")
        return []

    matched = []
    skipped_ts = 0
    skipped_level = 0
    total = 0

    with open(ALERTS_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Timestamp filter
            alert_dt = parse_alert_ts(alert)
            if alert_dt is None:
                skipped_ts += 1
                continue
            if alert_dt.tzinfo is None:
                alert_dt = alert_dt.replace(tzinfo=timezone.utc)
            if not (start_dt <= alert_dt <= end_dt):
                continue

            # Level filter
            try:
                level = int((alert.get("rule") or {}).get("level", 0))
            except (ValueError, TypeError):
                level = 0
            if level < min_level:
                skipped_level += 1
                continue

            matched.append(alert)

    log.info(
        f"Scanned {total} lines → {len(matched)} in window "
        f"[{start_dt.strftime('%H:%M:%S')} – {end_dt.strftime('%H:%M:%S')}]  "
        f"skipped: ts={skipped_ts} level={skipped_level}"
    )
    return matched


# ── batch file ────────────────────────────────────────────────────────────────

def write_batch(alerts: list[dict], start_dt: datetime, end_dt: datetime) -> Path:
    """Write alerts to a JSONL batch file in pending/."""
    stamp = start_dt.strftime("%Y%m%d_%H%M%S")
    fname = f"batch_{stamp}.jsonl"
    path  = PENDING_DIR / fname

    meta = {
        "_batch_meta": True,
        "window_start": start_dt.isoformat(),
        "window_end":   end_dt.isoformat(),
        "alert_count":  len(alerts),
        "created_at":   datetime.now(timezone.utc).isoformat(),
    }

    with open(path, "w", encoding="utf-8") as f:
        # First line is metadata (prefixed so it's skippable)
        f.write(json.dumps(meta) + "\n")
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    log.info(f"Batch written → {path}  ({len(alerts)} alerts)")
    return path


def read_batch(path: Path) -> tuple[dict, list[dict]]:
    """Read a batch file, returning (meta, alerts)."""
    meta = {}
    alerts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("_batch_meta"):
                meta = obj
            else:
                alerts.append(obj)
    return meta, alerts


# ── xai sender ────────────────────────────────────────────────────────────────

def send_to_xai(alert: dict, dry_run: bool = False) -> bool:
    """POST a single native Wazuh alert to XAI wrapped under 'alert' key."""
    rule    = alert.get("rule") or {}
    rule_id = rule.get("id", "?")
    level   = rule.get("level", "?")
    desc    = str(rule.get("description", ""))[:50]

    if dry_run:
        log.info(f"  [DRY] rule={rule_id} level={level}  {desc}")
        return True

    try:
        resp = requests.post(
            XAI_URL,
            json={"alert": alert},   # native Wazuh format, perfectly nested
            timeout=XAI_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code in (200, 201, 202, 204):
            log.info(f"  ✓ rule={rule_id} level={level}  {desc}")
            return True
        else:
            log.warning(f"  ✗ XAI {resp.status_code}  rule={rule_id}  {resp.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        log.warning(f"  ✗ timeout  rule={rule_id}")
        return False
    except Exception as e:
        log.error(f"  ✗ request error  rule={rule_id}: {e}")
        return False


def process_batch(path: Path, dry_run: bool = False) -> tuple[int, int]:
    """
    Process a batch file — send each alert to XAI.
    Returns (ok, errors).
    Moves file to done/ or failed/ accordingly.
    """
    log.info(f"Processing batch: {path.name}")
    meta, alerts = read_batch(path)

    if meta:
        log.info(
            f"  Window: {meta.get('window_start','')} → {meta.get('window_end','')}"
            f"  Alerts: {meta.get('alert_count', len(alerts))}"
        )

    ok = err = 0
    for alert in alerts:
        if send_to_xai(alert, dry_run=dry_run):
            ok += 1
        else:
            err += 1
        time.sleep(0.05)   # gentle pacing — don't flood XAI

    log.info(f"  Batch done — sent: {ok}  errors: {err}")

    if not dry_run:
        dest_dir = DONE_DIR if err == 0 else FAILED_DIR
        dest = dest_dir / path.name
        shutil.move(str(path), str(dest))
        log.info(f"  → moved to {dest_dir.name}/")

    return ok, err


# ── retry failed ─────────────────────────────────────────────────────────────

def retry_failed(dry_run: bool = False) -> tuple[int, int]:
    failed_files = sorted(FAILED_DIR.glob("batch_*.jsonl"))
    if not failed_files:
        log.info("No failed batches to retry.")
        return 0, 0

    log.info(f"Retrying {len(failed_files)} failed batch(es) …")
    total_ok = total_err = 0

    for path in failed_files:
        # Move back to pending first
        pending_path = PENDING_DIR / path.name
        shutil.move(str(path), str(pending_path))
        ok, err = process_batch(pending_path, dry_run=dry_run)
        total_ok += ok
        total_err += err

    return total_ok, total_err


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scheduled Wazuh batch processor → XAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--window",       type=int,  default=WINDOW_MIN,
                        help=f"Time window in minutes (default: {WINDOW_MIN})")
    parser.add_argument("--min-level",    type=int,  default=MIN_LEVEL,
                        help=f"Minimum rule.level (default: {MIN_LEVEL})")
    parser.add_argument("--dry-run",      action="store_true",
                        help="Write batch file but don't POST to XAI")
    parser.add_argument("--dump-only",    action="store_true",
                        help="Write batch file only, skip XAI entirely")
    parser.add_argument("--replay",       type=str,  default=None, metavar="FILE",
                        help="Replay a specific batch file to XAI")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Retry all failed batch files")
    parser.add_argument("--reset",        action="store_true",
                        help="Clear last-processed timestamp before running")
    args = parser.parse_args()

    ensure_dirs()
    state = load_state()

    run_start = datetime.now(timezone.utc)
    log.info(f"{'='*55}")
    log.info(f"XAI Batch Processor  window={args.window}m  level>={args.min_level}")
    log.info(f"Last run: {state.get('last_ts', 'never')}")

    # ── replay mode ──────────────────────────────────────────────────
    if args.replay:
        path = Path(args.replay)
        if not path.exists():
            log.error(f"File not found: {path}")
            sys.exit(1)
        ok, err = process_batch(path, dry_run=args.dry_run)
        log.info(f"Replay complete — ok={ok} errors={err}")
        return

    # ── retry failed mode ─────────────────────────────────────────────
    if args.retry_failed:
        ok, err = retry_failed(dry_run=args.dry_run)
        log.info(f"Retry complete — ok={ok} errors={err}")
        return

    # ── normal run ────────────────────────────────────────────────────
    if args.reset:
        state["last_ts"] = None
        log.info("State reset — will process last window from scratch")

    start_dt, end_dt = window_bounds(args.window, state.get("last_ts"))
    log.info(f"Window: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} → {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. Read matching alerts from alerts.json
    alerts = read_window(start_dt, end_dt, args.min_level)

    if not alerts:
        log.info("No alerts in window — nothing to do.")
        state["last_ts"] = end_dt.isoformat()
        save_state(state)
        return

    # 2. Write batch file
    batch_path = write_batch(alerts, start_dt, end_dt)

    # 3. Process (unless dump-only)
    if args.dump_only:
        log.info(f"--dump-only: batch written to {batch_path}, skipping XAI.")
    else:
        ok, err = process_batch(batch_path, dry_run=args.dry_run)
        state["batches_sent"] = state.get("batches_sent", 0) + 1
        state["alerts_sent"]  = state.get("alerts_sent", 0) + ok
        state["errors"]       = state.get("errors", 0) + err

    # 4. Advance timestamp cursor
    state["last_ts"] = end_dt.isoformat()
    if not args.dry_run:
        save_state(state)

    elapsed = (datetime.now(timezone.utc) - run_start).total_seconds()
    log.info(f"Run complete in {elapsed:.1f}s  "
             f"total sent={state['alerts_sent']}  errors={state['errors']}")
    log.info(f"{'='*55}")


if __name__ == "__main__":
    main()