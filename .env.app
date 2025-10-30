# === APP BACKEND ===
# Storage mode for explanations/feedback: "local" (default) OR "opensearch"
STORAGE_MODE=local

# If you later switch to OpenSearch, fill these:
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
OPENSEARCH_INDEX=explanations-v1
OPENSEARCH_INDEX_FEEDBACK=explain-feedback-v1
OPENSEARCH_SSL_VERIFY=false
