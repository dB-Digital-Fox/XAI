import os, json
from .storage import FeedbackStorage

class FeedbackManager:
    def __init__(self, mode: str = "local"):
        self.store = FeedbackStorage(mode=mode)

    def store_feedback(self, doc: dict):
        # trust_score clamp
        ts = int(doc.get("trust_score", 3))
        doc["trust_score"] = max(1, min(5, ts))
        self.store.store_feedback(doc)

    def metrics(self):
        path = "./data/outputs/feedback.jsonl"
        total = 0; overrides = 0; trust_sum = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    total += 1
                    try:
                        j = json.loads(line)
                        trust_sum += int(j.get("trust_score", 3))
                        overrides += 1 if j.get("overridden", False) else 0
                    except:
                        pass
        except FileNotFoundError:
            pass
        avg_trust = (trust_sum / total) if total else None
        return {"total_feedback": total, "avg_trust": avg_trust, "override_rate": (overrides/total if total else None)}
