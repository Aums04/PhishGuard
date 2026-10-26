import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.features import extract_features
from app.model import predict, load_metrics


def test_predict_returns_valid_probability():
    f = extract_features("https://github.com/anthropic")
    result = predict(f)
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["label"] in ("Phishing", "Legitimate")


def test_predict_phishing_like_url():
    f = extract_features("http://192.168.1.1@paypa1-secure.top/login/verify")
    result = predict(f)
    assert result["phishing_probability"] > 0.5


def test_metrics_loaded():
    metrics = load_metrics()
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert 0.0 <= metrics["precision"] <= 1.0
