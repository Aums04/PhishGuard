import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.features import extract_features
from app.rules import evaluate


def test_ip_url_flags_high_risk():
    f = extract_features("http://192.168.1.10/login/verify/account")
    result = evaluate(f)
    assert result["score"] > 0
    assert any(x["rule"] == "ip_host" for x in result["findings"])


def test_clean_legit_url_low_score():
    f = extract_features("https://github.com/anthropic/claude")
    result = evaluate(f)
    assert result["verdict"] == "Low Risk"


def test_typosquat_url_flagged():
    f = extract_features("http://paypa1-secure.com/login")
    result = evaluate(f)
    assert any(x["rule"] == "typosquat" for x in result["findings"])


def test_verdict_thresholds():
    f = extract_features("http://192.168.1.1@paypa1-secure.top/login/verify/account/signin")
    result = evaluate(f)
    assert result["score"] >= 50
    assert result["verdict"] == "High Risk"
