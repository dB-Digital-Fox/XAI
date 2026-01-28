# === APP BACKEND ===
# Storage mode for explanations/feedback: "local" (default) OR "opensearch"
STORAGE_MODE=opensearch

# If you later switch to OpenSearch, fill these:
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
OPENSEARCH_INDEX=wazuh-explain-v2
OPENSEARCH_INDEX_FEEDBACK=explain-feedback-v2
OPENSEARCH_SSL_VERIFY=false

# Default Wazuh Docker credentials
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=SecretPassword

# Other Configs
FEATURE_MAP_PATH=./config/feature_map.yaml
POLICY_MAP_PATH=./config/policy_map.yaml