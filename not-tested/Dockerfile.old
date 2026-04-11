FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# app code
COPY src /app/src

# model + feature map mounted via compose, but keep defaults too
ENV MODEL_PATH=/app/src/model_api/model.joblib
ENV FEATURE_MAP_PATH=/app/src/model_api/feature_map.yaml
ENV EXPLAINER_BACKEND=shap
ENV TOP_K_FEATURES=8
ENV EXPLAIN_INDEX=wazuh-explain-v1
ENV FEEDBACK_INDEX=wazuh-explain-feedback-v1
ENV OS_URL=https://wazuh-indexer:9200
ENV OS_USER=admin
ENV OS_PASS=admin
ENV OS_VERIFY_TLS=true

EXPOSE 8989
CMD ["uvicorn", "src.model_api.main:app", "--host", "0.0.0.0", "--port", "8989"]
