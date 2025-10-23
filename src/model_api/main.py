from __future__ import annotations
import os, time
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .util_explain import Explainer
from ..common.opensearch_client import OSClient
from .policy import Policy

POLICY_PATH = os.environ.get("POLICY_PATH", "/app/src/model_api/policy.yaml")
policy = Policy(POLICY_PATH)

EXPLAIN_INDEX = os.environ.get("EXPLAIN_INDEX", "wazuh-explain-v1")
FEEDBACK_INDEX = os.environ.get("FEEDBACK_INDEX", "wazuh-explain-feedback-v1")

app = FastAPI(title="Explainable SOC API", version="1.0")

# serve simple UI (feedback form)
static_dir = os.path.join(os.path.dirname(__file__), "ui")
app.mount("/ui", StaticFiles(directory=static_dir, html=True), name="ui")

explainer = Explainer(
    model_path=os.environ.get("MODEL_PATH", "/app/src/model_api/model.joblib"),
    feature_map_path=os.environ.get("FEATURE_MAP_PATH", "/app/src/model_api/feature_map.yaml"),
    backend=os.environ.get("EXPLAINER_BACKEND","shap"),
    top_k=int(os.environ.get("TOP_K_FEATURES","8"))
)
osc = OSClient()

EXPLAIN_MAPPING = {
  "properties": {
    "alert_id": {"type": "keyword"},
    "@timestamp": {"type":"date"},
    "model":{"type":"keyword"},
    "backend":{"type":"keyword"},
    "score":{"type":"float"},
    "class_prob":{"properties":{"neg":{"type":"float"},"pos":{"type":"float"}}},
    "top_features":{"type":"nested","properties":{
      "feature":{"type":"keyword"},
      "contribution":{"type":"float"}}},
    "decisive_events":{"type":"nested","properties":{
      "ts":{"type":"date"},
      "type":{"type":"keyword"},
      "snippet":{"type":"text"}}},
    "raw_hash":{"type":"keyword"},

    "criticality": {
      "properties": {
        "tag": {"type":"keyword"},
        "score": {"type":"float"},
        "reasons": {"type":"keyword"},
        "triage_text": {"type":"text"},
        "recommendations": {"type":"keyword"}
      }
    },
    "health": {
      "properties": {
        "feature_coverage_pct":{"type":"float"},
        "missing_features":{"type":"keyword"},
        "model_staleness_days":{"type":"integer"},
        "pipeline_ok":{"type":"boolean"}
      }
    }
  }
}

FEEDBACK_MAPPING = {
  "properties": {
    "alert_id":{"type":"keyword"},
    "@timestamp":{"type":"date"},
    "trust_score":{"type":"integer"},
    "overridden":{"type":"boolean"},
    "decision_ms":{"type":"long"}
  }
}

@app.on_event("startup")
def ensure_indices():
    osc.ensure_index(EXPLAIN_INDEX, EXPLAIN_MAPPING)
    osc.ensure_index(FEEDBACK_INDEX, FEEDBACK_MAPPING)

class ScoreExplainIn(BaseModel):
    alert_id: str
    alert: dict

@app.post("/score_explain")
def score_explain(body: ScoreExplainIn):
    start = time.time()
    try:
        exp = explainer.explain(body.alert)
    except Exception as e:
        raise HTTPException(400, f"Explain error: {e}")
    # Build a simple "feature used" mask: non-default means "used"
    feature_names = explainer.feature_names
    vals = explainer.xform(body.alert)
    defaults = [f.get("default", 0) for f in explainer.feature_defs]
    used_mask = [bool(v != d and v is not None) for v, d in zip(vals, defaults)]

    # Apply policy to get criticality + health
    pol = policy.decide(
        score=exp["score"],
        alert=body.alert,
        feature_used_mask=used_mask,
        feature_names=feature_names,
        model_path=os.environ.get("MODEL_PATH", "/app/src/model_api/model.joblib")
    )
    doc = {
        "alert_id": body.alert_id,
        "@timestamp": body.alert.get("@timestamp"),
        **exp,
        **pol, 
        "raw_hash": str(abs(hash(str(body.alert))))
    }
    r = osc.index_doc(EXPLAIN_INDEX, doc, doc_id=f"{body.alert_id}")
    return {"indexed": r.status_code in (200,201), "explanation": exp}

class FeedbackIn(BaseModel):
    alert_id: str
    trust_score: int  # 1..5
    overridden: bool
    decision_ms: int

@app.post("/feedback")
def feedback(body: FeedbackIn):
    doc = {"@timestamp": int(time.time()*1000), **body.model_dump()}
    r = osc.index_doc(FEEDBACK_INDEX, doc)
    return {"ok": r.status_code in (200,201)}
