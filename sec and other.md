
---

### That’s everything you need to spin this up:
- API + model explainer
- Wazuh integration hook
- Dashboard side panel visuals (top features, decisive events, score)
- In-app feedback page and dashboard link

If you want, I can also generate a ready-made **OpenSearch saved-objects export** (.ndjson) for one-click import — but the Vega specs above are often the fastest path.

In-app feedback (two click flow)

Put a Markdown panel on the dashboard with this link:
[Give feedback on this alert](/app/explainable-soc/ui/feedback.html?alert_id={{your_control.value}})
If you host the API behind another domain/port, use the full URL, e.g.:
http://<explainer-host>:8989/ui/feedback.html?alert_id={{your_control.value}}
The page automatically captures “decision time” (ms) from open→submit and POSTs to /feedback.
You can also add a Dashboard drilldown button that opens that URL with the selected alert_id.

### Training workflow (recommended)

Label source

- Start with your analyst feedback and action/override as labels (1 when escalated/confirmed/blocked; 0 when dismissed).

- Fall back to rule‐level heuristics (e.g., certain rule IDs as positive) to bootstrap.

Feature map

- Keep feature_map.yaml aligned with your alerts.

- Add template_id, rolling counts (e.g., auth_failures_5m), risk scores, geo signals, user/device risk.

Train

- python -m src.training.train_model (envs for OS creds).

- Swap model to XGBoost/LightGBM later (TreeExplainer still works great).

Calibrate

- Keep isotonic calibration; it improves the score gauge semantics.

Ship

- Copy the produced src/model_api/model.joblib into the API, restart the container.

- SHAP/LIME explanations will start populating wazuh-explain-v1.

Manual: how to make the feature set larger (safely)

Add canonical fields in _canonicalize:

Examples: src_country_risk, internal_to_internal, user_risk_score, device_risk_score, geo_distance_km, asn_reputation, rolling_auth_fail_5m, etc.

All canonical fields are plain numbers or 0/1 flags.

Expose new fields in the feature map:

Append new entries to config/feature_map.yaml (or JSON) in the exact order you want the model to see.

Keep names short, stable, snake_case.

Retrain once:

Delete training/feature_names.json (it will be regenerated).

Train; the API will then use the new order automatically.

Version control the feature map:

Treat it like schema. If you remove features, retrain, and restart the API to avoid length mismatches.

Guardrails:

Always coerce to numeric in _apply_feature_map (already done).

For rolling counters (e.g., auth_fail_5m), calculate upstream or add a pre-processor in your data ingestion.