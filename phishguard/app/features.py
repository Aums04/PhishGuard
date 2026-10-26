"""Static, string-only URL feature extraction. No network requests are made."""
import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "top", "xyz", "tk", "work", "click", "gq", "ml", "cf", "loan", "win"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "account", "confirm",
                        "signin", "banking", "password", "suspend", "urgent", "billing"}
KNOWN_BRANDS = ["paypal", "google", "microsoft", "amazon", "apple", "facebook",
                "instagram", "netflix", "bankofamerica", "chase", "wellsfargo", "icici", "hdfc"]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _brand_typosquat_hit(hostname: str):
    """Return the brand name if hostname closely resembles a known brand
    but is not that brand's real domain."""
    if not hostname:
        return None
    first_label = hostname.split(".")[0]
    # candidate tokens: the whole first label, and its hyphen-separated parts
    tokens = [first_label] + first_label.split("-")
    for brand in KNOWN_BRANDS:
        if brand in hostname and not hostname.endswith(f"{brand}.com"):
            return brand
        for token in tokens:
            if token and abs(len(token) - len(brand)) <= 2 and _levenshtein(token, brand) <= 2 and token != brand:
                return brand
    return None


def extract_features(raw_url: str) -> dict:
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url  # allow bare domains, still never fetched

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    tld = hostname.split(".")[-1] if "." in hostname else ""
    subdomain_count = max(hostname.count(".") - 1, 0)
    digits = sum(c.isdigit() for c in hostname)
    letters = sum(c.isalpha() for c in hostname)
    typosquat_brand = _brand_typosquat_hit(hostname)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "at_symbol": int("@" in url),
        "digit_count_host": digits,
        "special_char_count": len(re.findall(r"[^a-zA-Z0-9.\-/:]", url)),
        "subdomain_count": subdomain_count,
        "is_ip_host": int(_is_ip_hostname(hostname)),
        "uses_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(hostname in URL_SHORTENERS),
        "digit_letter_ratio": round(digits / letters, 3) if letters else 0.0,
        "double_slash_in_path": path.count("//"),
        "suspicious_keyword_count": sum(k in full for k in SUSPICIOUS_KEYWORDS),
        "typosquat_brand": typosquat_brand or "",
        "is_typosquat": int(typosquat_brand is not None),
    }
    features["hostname"] = hostname
    features["raw_url"] = raw_url.strip()
    return features


FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "dot_count", "hyphen_count",
    "at_symbol", "digit_count_host", "special_char_count", "subdomain_count",
    "is_ip_host", "uses_https", "has_port", "suspicious_tld", "is_shortener",
    "digit_letter_ratio", "double_slash_in_path", "suspicious_keyword_count",
    "is_typosquat",
]
