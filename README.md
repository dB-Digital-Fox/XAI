# Explainable SOC for Wazuh (SHAP/LIME)

## Run
1. Put your trained scikit-learn classifier in `src/model_api/model.joblib`.
2. Adjust `src/model_api/feature_map.yaml` to match your alert fields.
3. `docker compose up -d` (set OS_URL/OS_USER/OS_PASS envs).

API runs on `http://localhost:8989`.

## Wazuh Integration
- Copy `src/integration/wazuh_explainer.py` to `/var/ossec/integrations/` on the Manager.
- `chmod +x /var/ossec/integrations/wazuh_explainer.py`
- Add the `<integration>` block for your ML rule IDs.
- `service wazuh-manager restart`

## OpenSearch Dashboards
- Create three **Vega** visualizations and paste the JSON from `dashboards/*.vega.json`.
- Create an **Options list** control bound to `wazuh-explain-v1.alert_id`.
- Assemble into a dashboard.
- (Optional) Drilldown link from alert tables to this dashboard with `alert_id` filter.

## Feedback
- The API serves a simple form at `/ui/feedback.html`.
- Add a Markdown panel with a link to `http://<host>:8989/ui/feedback.html?alert_id={{selected}}`.

## Indices
- Explanations: `wazuh-explain-v1` (doc id = `alert_id`)
- Feedback: `wazuh-explain-feedback-v1`

## Test locally
```bash
curl -X POST http://localhost:8989/score_explain \
  -H 'Content-Type: application/json' \
  -d '{
    "alert_id":"A-123",
    "alert":{
      "@timestamp":"2025-10-13T10:00:00Z",
      "data":{"srcport":22,"dstport":3389,"geoip":{"src":{"risk_score":7},"dst":{"risk_score":3}}},
      "enrich":{"auth_fail_5m":12,"user":{"risk":0.8}},
      "win":{"event":{"code":4625}},
      "evidence":[{"@timestamp":"2025-10-13T09:58:00Z","kind":"auth-fail","message":"Failed login for user x"}]
    }
  }'
# Then open http://localhost:8989/ui/feedback.html?alert_id=A-123 and submit feedback.
