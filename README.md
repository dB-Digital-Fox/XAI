# Explainable SOC for Wazuh (XAI Pipeline)

A local-first, explainability-augmented Security Operations Centre (SOC) backend that enriches Wazuh alerts with calibrated risk scores, SHAP-based feature attributions, and policy-driven recommendations — indexed into OpenSearch and visualised through a custom Vega dashboard.

---

## Architecture Overview

```
Wazuh Manager
  │
  ├──► /var/ossec/logs/alerts/alerts.json   (native JSON, written continuously)
  │         │
  │         └──► alerts_xai_bridge.py       (tails the file, zero reconstruction)
  │                   │
  │                   └──► POST { "alert": <wazuh_doc> } → XAI API :8080/explain
  │                               │
  │                               ├── extract_features()    (features.py)
  │                               ├── predict_proba()       (model.pkl)
  │                               ├── TreeSHAP / KernelSHAP / FI fallback
  │                               └── store_explanation()   → wazuh-explain-v2
  │
  └──► Filebeat → wazuh-alerts-*            (raw alerts, Discover / A/B view)
```

The bridge reads directly from Wazuh's native `alerts.json` — bypassing Filebeat's dot-notation flattening — so every alert arrives at XAI with fully nested `rule`, `data`, `agent`, and `decoder` objects, exactly as Wazuh wrote them.

---

## Quick Start

### 1. Train the model

```bash
# Copy your alert dumps into data/filtered/
cp /path/to/alerts/*.json data/filtered/

# Train (outputs model.pkl, feature_names.json, shap_bg.npy)
python3 training/train.py 2>&1 | tee /tmp/train.log

# Verify class balance — target at least 25% positives
grep "Class distribution" /tmp/train.log
```

### 2. Start the XAI API

```bash
# Install dependencies
pip3 install -r requirements.txt

# Start API on port 8080
uvicorn src.app:app --host 0.0.0.0 --port 8080

# Verify it's up
curl http://localhost:8080/metrics
```

### 3. Start the bridge

```bash
# Tail alerts.json and forward to XAI (requires root to read Wazuh logs)
sudo python3 alerts_xai_bridge.py --min-level 1

# Dry run first to verify format
sudo python3 alerts_xai_bridge.py --dry-run --debug

# Backfill the last hour before going live
sudo python3 alerts_xai_bridge.py --backfill 500 --min-level 1
```

### 4. Install as a systemd service

```bash
sudo cp alerts_xai_bridge.py /opt/wazuh-xai-bridge/
sudo cp alerts-xai-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now alerts-xai-bridge
sudo journalctl -fu alerts-xai-bridge
```

---

## Wazuh Integration

The bridge is the only integration needed. Remove or disable the old `<integration>` block from `ossec.conf` if present — the bridge replaces it.

Ensure `jsonout_output` is enabled in `/var/ossec/ossec.conf`:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <log_alert_level>1</log_alert_level>
</global>
```

For **FortiGate** logs (which produce the richest feature vectors), configure your appliance to send syslog to the Wazuh manager and add a monitored file:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/xai-test/forti-test.log</location>
</localfile>
```

---

## Injecting Test Logs

Two scripts are provided for generating realistic test data:

```bash
# General mixed log batch (38 logs — SSH, sudo, FortiGate, web, dpkg, systemd)
python3 inject_logs.py --delay 1 --watch

# High-severity scenarios (10 scenarios, levels 12–15)
python3 inject_high_severity.py --list       # preview all scenarios
python3 inject_high_severity.py              # fire all 10
python3 inject_high_severity.py --scenario 4 # Log4Shell exploit only
```

Both scripts use `logger` to send through the system syslog socket (`/dev/log` → journald → Wazuh) — the same path as real system events — so they appear in both Discover and the XAI dashboard.

---

## Batch Processing (Alternative to Live Bridge)

For environments where a long-running tail process is undesirable, a scheduled batch processor is also available:

```bash
# Process the last 10-minute window from alerts.json
sudo python3 batch_processor.py --window 10 --min-level 1

# Dry run — write batch file but do not POST to XAI
sudo python3 batch_processor.py --dump-only --window 60

# Retry any failed batches from a previous run
sudo python3 batch_processor.py --retry-failed
```

Install as a cron job for fully automatic operation:

```
*/10 * * * * root /usr/bin/python3 /opt/wazuh-xai-bridge/batch_processor.py \
  --window 10 --min-level 1 >> /var/log/xai-batch.log 2>&1
```

---

## OpenSearch Dashboards

### Index patterns

Create the index pattern. Go to Indexer Management → Dev Tools and run:
```json
POST .kibana/_doc/index-pattern:wazuh-xai-v3
{
  "type": "index-pattern",
  "index-pattern": {
    "title": "wazuh-explain-*",
    "timeFieldName": "@timestamp"
  }
}
```

This registers the XAI index with OpenSearch Dashboards so the DQL search bar, time picker, and Add Filter controls all recognise its fields. Without this step the Vega visualisation still renders, but the dashboard-level filters and time range have no effect on it.

| Index | Content |
|---|---|
| `wazuh-alerts-*` | Raw Wazuh alerts (Discover, A/B raw view) |
| `wazuh-explain-v3` | XAI-enriched explanations (custom Vega dashboard) |

### Dashboard setup

1. Create index pattern for `wazuh-explain-v2` with time field `@timestamp`.
2. Create a new dashboard and add a **Vega** visualisation.
3. Paste the Vega JSON from `dashboards/xai_dashboard.vega.json`.
4. The dashboard renders three panels: **Logs** (paginated list), **Features & Scoring** (gauge + SHAP contributions), **Raw Alert** (monospace field-by-field view).

---

## API Reference

### `POST /explain`

Accepts a Wazuh alert and returns a risk score, label, top SHAP features, and a policy-driven recommendation.

**Request:**
```json
{
  "alert": {
    "timestamp": "2026-03-20T13:25:19.819+0100",
    "rule": { "level": 6, "id": "81629", "description": "Fortigate attack dropped.", "groups": ["fortigate", "attack"] },
    "agent": { "id": "000", "name": "db-wazuh" },
    "decoder": { "name": "fortigate-firewall-v5" },
    "data": { "srcip": "147.203.255.20", "dstip": "147.175.163.214", "dstport": "161", "severity": "low", "action": "dropped", "service": "SNMP", "subtype": "ips" },
    "full_log": "...",
    "location": "127.0.0.1"
  }
}
```

**Response:**
```json
{
  "ok": true,
  "explanation": {
    "doc_id": "1761606001.21886",
    "model_version": "v0.2",
    "predicted_score": 0.71,
    "predicted_label": "malicious",
    "top_features": [
      { "feature": "severity_ord", "value": 1.0, "impact": 0.18 },
      { "feature": "dst_svc_sensitive", "value": 1.0, "impact": 0.14 }
    ],
    "reason": "Top impact: severity_ord, dst_svc_sensitive",
    "recommendation": "Check IPS hits, correlate"
  }
}
```

### `POST /feedback`

Stores analyst feedback for a processed alert.

```json
{ "alert_id": "1761606001.21886", "trust_score": 4, "overridden": false, "decision_ms": 12000 }
```

### `GET /metrics`

Returns aggregated feedback statistics.

```json
{ "trust_mean": 4.1, "override_rate": 0.14, "decision_ms": { "p50": 18000, "p95": 55000 }, "n": 84 }
```

---

## Configuration

### Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PARTS_GLOB` | `./data/filtered/part_*.json` | Training data glob pattern |
| `SHAP_BG_K` | `60` | SHAP k-means background size |
| `MODEL_PATH` | `./training/model.pkl` | Trained model path |
| `TOP_K` | `10` | Top features returned per alert |
| `TOP_K_MIN` | `10` | Minimum top-k floor |
| `STORAGE_MODE` | `local` | `local` or `opensearch` |
| `OPENSEARCH_URL` | `https://127.0.0.1:9200` | OpenSearch endpoint |
| `FEATURE_MAP_PATH` | `./config/feature_map.yaml` | Feature schema |

### Feature map

Edit `config/feature_map.yaml` to add, remove, or rename features. After any change, retrain — the saved `feature_names.json` must match what `extract_features()` produces at inference time.

### Policy map

`config/policy_map.yaml` controls per-source thresholds, severity bands, and recommendations. The `source` is inferred from `decoder.name` and `rule.groups` at inference time:

| Source | Examples |
|---|---|
| `network` | FortiGate, Cisco, UniFi |
| `endpoint` | Windows Event Log, Linux sshd/sudo |
| `server` | OpenStack, generic syslog |

---

## Project Structure

```
XAI/
├── .venv/                           # Python virtual environment
├── config/                          # Configuration files
│   ├── feature_map.yaml             # Feature schema and defaults
│   └── policy_map.yaml              # Per-source thresholds and recommendations
├── dashboard/                       # Vega dashboard JSON specs
├── data/
│   ├── filtered/                    # Preprocessed training alert dumps (JSON/JSONL)
│   ├── outputs/                     # Training and evaluation outputs
│   ├── parts/                       # Raw alert shards
│   └── sample/                      # Sample alerts for manual testing
├── scripts/
│   └── drain3_online.py             # Online log template mining (Drain3)
├── src/
│   ├── common/                      # Shared utilities (OpenStack I/O, helpers)
│   ├── __init__.py
│   ├── app.py                       # FastAPI: /explain, /feedback, /metrics
│   ├── features.py                  # Source detection, canonicalization, feature vector
│   ├── feedback.py                  # Trust / override / latency aggregation
│   ├── model.py                     # Explainer (TreeSHAP → KernelSHAP → FI fallback)
│   ├── policy.py                    # Per-source policy application
│   ├── storage.py                   # Local JSONL + optional OpenSearch indexing
│   └── wazuh_integration.py         # Index template helpers
├── training/
│   ├── feature_names.json           # Stable feature order (artifact output)
│   ├── json-parser.py               # Alert dump preprocessing utility
│   ├── model.pkl                    # Trained model (artifact output)
│   ├── shap_bg.npy                  # SHAP k-means background (artifact output)
│   └── train.py                     # Weak labels + calibrated RF + SHAP background
├── wazuh-connections/
│   ├── batch_processing/            # Scheduled batch processor scripts
│   ├── os_xai_bridge/
│   │   ├── os_xai_bridge.py         # OpenSearch-based bridge (alternative)
│   │   ├── wazuh-install-script.sh  # Installation helper
│   │   └── wazuh-xai-bridge.service # Systemd service unit
│   ├── alerts_xai_bridge.py         # Live tail bridge: alerts.json → XAI (primary)
│   ├── alerts-xai-bridge.service    # Systemd service unit for live bridge
│   └── wazuh-install-script.sh      # Wazuh-side installation script
├── .env.app                         # API runtime environment variables
├── .env.app.example                 # Template for .env.app
├── .env.train                       # Training environment variables
├── .env.train.example               # Template for .env.train
├── .gitignore
├── consistency_check.py             # Feature schema / artifact consistency checker
├── docker-compose.yml               # Compose file for containerised deployment
├── inject_logs.py                   # Test log injector (general, 38 scenarios)
├── load_and_report.py               # Model evaluation and reporting utility
├── README.md
├── requirements.txt                 # Production dependencies
└── sec and other.md                 # Security notes and miscellaneous documentation
```

---

## Troubleshooting

**All alerts scored as benign (score ≈ 0.0):**
Check that `data.*` fields are non-empty in arriving alerts. Run with `--debug` on the bridge to inspect the full payload. If only `rule_level` is non-zero, the alert type is being routed to `_map_generic` — check `_detect_source()` in `features.py` and add the decoder name to `LINUX_DECODERS` if needed. Retrain after fixing.

**High score on benign-looking alerts (systemd, journald):**
The model learned `rule_level` as a near-exclusive predictor. Retrain after deploying the updated `features.py` and `train.py` — the new weak labels and extended `_map_linux()` mapper provide significantly richer signal for syslog events.

**Bridge fails to open `alerts.json`:**
Run as root or add your user to the `wazuh` group: `sudo usermod -aG wazuh $USER`. Confirm `jsonout_output=yes` in `ossec.conf` and that `wazuh-manager` is running.

**XAI returns 422 Unprocessable Entity:**
The payload is missing the `alert` wrapper key. Confirm the bridge sends `{"alert": <doc>}` not the raw document at the top level.

**SHAP values are all zero / only one feature shown:**
`feature_names.json` is stale relative to `features.py`. Delete both `feature_names.json` and `shap_bg.npy` and retrain from scratch.