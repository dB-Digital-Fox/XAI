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
            
            # Load Config
            host = os.getenv("OPENSEARCH_HOST", "localhost")
            port = int(os.getenv("OPENSEARCH_PORT", "9200"))
            verify = os.getenv("OPENSEARCH_SSL_VERIFY", "false").lower() == "true"
            
            # Load Credentials (THIS WAS MISSING)
            user = os.getenv("OPENSEARCH_USERNAME", "admin")
            password = os.getenv("OPENSEARCH_PASSWORD", "SecretPassword")
            
            self.index = os.getenv("OPENSEARCH_INDEX", "wazuh-explain-v1")
            self.index_feedback = os.getenv("OPENSEARCH_INDEX_FEEDBACK", "explain-feedback-v1")
            
            # Connect with Auth + Force HTTPS
            self.os = OpenSearch(
                hosts=[{"host": host, "port": port, "scheme": "https"}],
                http_auth=(user, password),  # <--- PASS CREDENTIALS HERE
                verify_certs=verify,
                ssl_show_warn=False
            )
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
