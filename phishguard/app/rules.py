"""Deterministic rule engine. Each rule is independent of the ML model."""

SEVERITY_WEIGHT = {"low": 10, "medium": 20, "high": 35}


def _rule_ip_host(f):
    return (bool(f["is_ip_host"]), "Hostname is a raw IP address instead of a domain name.", "high")


def _rule_typosquat(f):
    fired = bool(f["is_typosquat"])
    ev = f"Resembles the brand '{f['typosquat_brand']}' but is not its real domain." if fired else ""
    return (fired, ev, "high")


def _rule_at_symbol(f):
    return (bool(f["at_symbol"]), "URL contains '@', which can hide the real destination host.", "high")


def _rule_shortener(f):
    return (bool(f["is_shortener"]), "URL uses a known link-shortening service, hiding the real destination.", "medium")


def _rule_suspicious_tld(f):
    return (bool(f["suspicious_tld"]), "Domain uses a top-level domain commonly abused for phishing.", "medium")


def _rule_excess_subdomains(f):
    fired = f["subdomain_count"] > 3
    return (fired, f"Hostname has {f['subdomain_count']} subdomains (unusually deep).", "medium")


def _rule_no_https(f):
    return (not bool(f["uses_https"]), "Connection is not HTTPS.", "low")


def _rule_suspicious_keywords(f):
    fired = f["suspicious_keyword_count"] >= 2
    return (fired, f"URL contains {f['suspicious_keyword_count']} sensitive/urgency keywords (e.g. login, verify, secure).", "medium")


def _rule_long_url(f):
    fired = f["url_length"] > 90
    return (fired, f"URL is unusually long ({f['url_length']} characters).", "low")


def _rule_digit_heavy_host(f):
    fired = f["digit_letter_ratio"] > 0.25
    return (fired, "Hostname has an unusually high digit-to-letter ratio.", "low")


RULES = [
    _rule_ip_host, _rule_typosquat, _rule_at_symbol, _rule_shortener,
    _rule_suspicious_tld, _rule_excess_subdomains, _rule_no_https,
    _rule_suspicious_keywords, _rule_long_url, _rule_digit_heavy_host,
]


def evaluate(features: dict) -> dict:
    findings = []
    score = 0
    for rule in RULES:
        fired, evidence, severity = rule(features)
        if fired:
            findings.append({"rule": rule.__name__.replace("_rule_", ""), "evidence": evidence, "severity": severity})
            score += SEVERITY_WEIGHT[severity]
    score = min(score, 100)
    if score >= 50:
        verdict = "High Risk"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"
    return {"score": score, "verdict": verdict, "findings": findings}
