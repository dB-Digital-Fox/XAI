from joblib import load
import numpy as np
from feature_builder import FeatureBuilder
import os, json

FMAP_PATH   = os.environ.get("FEATURE_MAP_PATH", "src/model_api/feature_map.yaml")
MODEL_PATH  = os.environ.get("MODEL_PATH_IN", "src/model_api/model.joblib")

fb = FeatureBuilder(FMAP_PATH)
clf = load(MODEL_PATH)

#Create a synthetic alert (replaced by real one)
alert = {
  "data":{"srcport":22,"dstport":3389,"geoip":{"src":{"risk_score":7},"dst":{"risk_score":3}}},
  "enrich":{"auth_fail_5m":12,"user":{"risk":0.8}},
  "win":{"event":{"code":4625}}
}

x = fb.transform_one(alert).reshape(1, -1)  # model expects 2D array
print("proba:", clf.predict_proba(x)[0].tolist())