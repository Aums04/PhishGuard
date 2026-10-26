"""Loads the trained model and produces explainable predictions."""
import os
import json
import pickle
import pandas as pd

from app.features import FEATURE_COLUMNS

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "..", "models", "phishguard_model.pkl")
METRICS_PATH = os.path.join(HERE, "..", "models", "metrics.json")

_model = None
_metrics = None


def load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


def load_metrics():
    global _metrics
    if _metrics is None:
        with open(METRICS_PATH) as f:
            _metrics = json.load(f)
    return _metrics


def predict(features: dict) -> dict:
    clf = load_model()
    row = pd.DataFrame([{k: features[k] for k in FEATURE_COLUMNS}])
    proba = clf.predict_proba(row)[0]
    phishing_proba = float(proba[1])
    label = "Phishing" if phishing_proba >= 0.5 else "Legitimate"

    # Explainability: combine global feature importance with this URL's
    # own (nonzero / notable) feature values to produce a human-readable
    # contribution list.
    importances = load_metrics()["feature_importances"]
    contributions = []
    for col in FEATURE_COLUMNS:
        val = features[col]
        weight = importances.get(col, 0)
        if val not in (0, 0.0, False) and weight > 0:
            contributions.append((col, val, weight))
    contributions.sort(key=lambda x: x[2], reverse=True)
    top_contributions = [
        {"feature": c[0], "value": c[1], "importance": round(c[2], 4)}
        for c in contributions[:6]
    ]

    return {
        "phishing_probability": round(phishing_proba, 4),
        "label": label,
        "top_contributions": top_contributions,
    }
