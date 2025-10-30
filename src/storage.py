import os, json
from datetime import datetime
from dotenv import load_dotenv
load_dotenv(".env.app")

OUT_DIR = "./data/outputs"
EXPL_PATH = os.path.join(OUT_DIR, "explanations.jsonl")
FEED_PATH = os.path.join(OUT_DIR, "feedback.jsonl")

class StorageManager:
    def __init__(self, mode: str = "local"):
        self.mode = mode.lower()
        os.makedirs(OUT_DIR, exist_ok=True)
        if self.mode == "opensearch":
            from opensearchpy import OpenSearch
            host = os.getenv("OPENSEARCH_HOST","localhost")
            port = int(os.getenv("OPENSEARCH_PORT","9200"))
            verify = os.getenv("OPENSEARCH_SSL_VERIFY","false").lower()=="true"
            self.index = os.getenv("OPENSEARCH_INDEX","explanations-v1")
            self.index_feedback = os.getenv("OPENSEARCH_INDEX_FEEDBACK","explain-feedback-v1")
            self.os = OpenSearch(hosts=[{"host":host,"port":port,"scheme":"https" if verify else "http"}], verify_certs=verify)
        else:
            self.os = None

    def store_explanation(self, doc: dict):
        doc["@ingested_at"] = datetime.utcnow().isoformat()+"Z"
        if self.mode == "opensearch" and self.os is not None:
            self.os.index(index=self.index, body=doc)
            return
        with open(EXPL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

class FeedbackStorage(StorageManager):
    def store_feedback(self, doc: dict):
        doc["@ingested_at"] = datetime.utcnow().isoformat()+"Z"
        if self.mode == "opensearch" and self.os is not None:
            self.os.index(index=self.index_feedback, body=doc)
            return
        with open(FEED_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
