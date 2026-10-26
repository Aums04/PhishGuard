"""Generates a curated labeled URL dataset for PhishGuard's demo model.
This is a synthetic/curated dataset for academic demonstration purposes —
NOT a live threat-intel feed. Limitation documented in PRD Section 10.
"""
import random
import csv

random.seed(42)

legit_domains = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "stackoverflow.com", "nytimes.com", "bbc.com", "reddit.com",
    "linkedin.com", "spotify.com", "netflix.com", "dropbox.com", "salesforce.com",
    "paypal.com", "adobe.com", "cloudflare.com", "mozilla.org", "python.org",
    "fcrit.ac.in", "mit.edu", "stanford.edu", "nasa.gov", "who.int",
    "icicibank.com", "hdfcbank.com", "irctc.co.in", "gov.in", "un.org",
]
legit_paths = ["", "/", "/about", "/products", "/blog/2024/update", "/docs/api",
               "/user/settings", "/search?q=test", "/careers", "/contact-us",
               "/news/latest", "/help/faq", "/account/profile", "/pricing"]

brands = ["paypal", "google", "microsoft", "amazon", "apple", "facebook",
          "instagram", "netflix", "bankofamerica", "chase", "wellsfargo", "icici", "hdfc"]
suspicious_tlds = ["zip", "top", "xyz", "tk", "work", "click", "gq", "ml", "cf", "loan", "win"]
shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
keywords = ["login", "verify", "secure", "update", "account", "confirm",
            "signin", "banking", "password", "suspend", "urgent", "billing"]

def typo_variant(brand):
    variants = [
        brand[:-1] + random.choice("qwertyuiopasdfghjklzxcvbnm"),
        brand.replace("o", "0").replace("l", "1"),
        brand + random.choice(["-secure", "-login", "-verify", "support"]),
        brand[:len(brand)//2] + brand[len(brand)//2+1:],
    ]
    return random.choice(variants)

rows = []

for _ in range(220):
    domain = random.choice(legit_domains)
    path = random.choice(legit_paths)
    url = f"https://{domain}{path}"
    rows.append((url, 0))

for _ in range(90):
    brand = random.choice(brands)
    fake_host = typo_variant(brand) + "." + random.choice(["com", "net", "info"] + suspicious_tlds)
    path = "/" + random.choice(keywords) + random.choice(["", ".php", "/update", "/account"])
    url = f"http://{fake_host}{path}"
    rows.append((url, 1))

for _ in range(50):
    ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    path = "/" + random.choice(keywords) + "/" + random.choice(brands)
    url = f"http://{ip}{path}"
    rows.append((url, 1))

for _ in range(40):
    short = random.choice(shorteners)
    code = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
    url = f"http://{short}/{code}"
    rows.append((url, 1))

for _ in range(60):
    brand = random.choice(brands)
    sub = ".".join([random.choice(keywords) for _ in range(random.randint(3,5))])
    tld = random.choice(suspicious_tlds + ["com"])
    url = f"http://{sub}.{brand}-verify.{tld}/{random.choice(keywords)}.php?id={random.randint(1000,9999)}"
    rows.append((url, 1))

for _ in range(30):
    brand = random.choice(brands)
    fake_host = random.choice(["192.168." + str(random.randint(0,255)) + "." + str(random.randint(1,254)),
                                "secure-" + random.choice(suspicious_tlds) + ".net"])
    url = f"http://{brand}.com@{fake_host}/login"
    rows.append((url, 1))

random.shuffle(rows)

with open("/home/claude/phishguard/data/urls_dataset.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    writer.writerows(rows)

print(f"Generated {len(rows)} rows: {sum(r[1] for r in rows)} phishing, {len(rows)-sum(r[1] for r in rows)} legitimate")
