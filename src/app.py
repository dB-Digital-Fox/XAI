import os, time
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from dotenv import load_dotenv

from .model import Explainer
from .features import extract_features
from .storage import StorageManager
from .feedback import FeedbackManager

load_dotenv(".env.app")

MODE = os.getenv("STORAGE_MODE", "local")  # "local" or "opensearch"

app = FastAPI(title="Explainable SOC Backend (Minimal)")

explainer = Explainer(model_path="./training/model.pkl")
storage = StorageManager(mode=MODE)
feedback_mgr = FeedbackManager(mode=MODE)

class ExplainIn(BaseModel):
    alert: Dict[str, Any]

class FeedbackIn(BaseModel):
    alert_id: str
    trust_score: int  # 1..5
    overridden: bool
    decision_ms: int

@app.post("/explain")
def explain(body: ExplainIn):
    alert = body.alert
    try:
        feats = extract_features(alert)
        exp = explainer.explain(alert, feats)
        # doc id: prefer alert "id" if present
        doc_id = str(alert.get("id") or int(time.time() * 1000))
        storage.store_explanation({"doc_id": doc_id, **exp})
        return {"ok": True, "explanation": {"doc_id": doc_id, **exp}}
    except Exception as e:
        raise HTTPException(400, f"explain error: {e}")

@app.post("/feedback")
def feedback(body: FeedbackIn):
    try:
        feedback_mgr.store_feedback(body.model_dump())
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, f"feedback error: {e}")

@app.get("/metrics")
def metrics():
    return feedback_mgr.metrics()

