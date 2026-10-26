import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.features import extract_features


def test_ip_host_detected():
    f = extract_features("http://192.168.1.10/login")
    assert f["is_ip_host"] == 1


def test_https_detected():
    f = extract_features("https://example.com")
    assert f["uses_https"] == 1
    f2 = extract_features("http://example.com")
    assert f2["uses_https"] == 0


def test_at_symbol_detected():
    f = extract_features("http://paypal.com@malicious.net/login")
    assert f["at_symbol"] == 1


def test_shortener_detected():
    f = extract_features("http://bit.ly/abc1234")
    assert f["is_shortener"] == 1


def test_typosquat_detected():
    f = extract_features("http://paypa1-secure.com/login")
    assert f["is_typosquat"] == 1


def test_legit_url_clean():
    f = extract_features("https://github.com/anthropic")
    assert f["is_ip_host"] == 0
    assert f["is_typosquat"] == 0
    assert f["is_shortener"] == 0


def test_suspicious_tld_detected():
    f = extract_features("http://secure-login.top/verify")
    assert f["suspicious_tld"] == 1
