# PhishGuard — Technical Design Document

## 1. Architecture

```
phishguard/
├── app/
│   ├── main.py            # Streamlit entrypoint — UI + page routing
│   ├── features.py        # Lexical/structural URL feature extraction
│   ├── rules.py            # Deterministic rule engine
│   ├── model.py            # ML load/predict + explainability helpers
│   ├── storage.py          # SQLite history read/write
│   └── report.py           # PDF report generation
├── data/
│   └── urls_dataset.csv    # Curated labeled dataset (url,label)
├── models/
│   ├── train.py             # Training script -> saves model + metrics
│   ├── phishguard_model.pkl
│   └── metrics.json
├── tests/
│   ├── test_features.py
│   ├── test_rules.py
│   └── test_model.py
└── docs/
    ├── PRD.md
    └── TECHNICAL_DESIGN.md
```

All three analysis layers (features, rules, model) are independent modules
with no cross-imports except `model.py` consuming `features.py` output.
This is what keeps the ML prediction and rule-engine finding *separable*
in the UI, per FR5.

## 2. Feature Extraction (`features.py`)
Static, string-only analysis of the URL — nothing is fetched over the
network. Features extracted:

- URL length, hostname length, path length
- Count of: dots, hyphens, '@', digits, special chars, subdomains
- Has IP address as hostname (bool)
- Uses HTTPS (bool, from scheme)
- Has port specified (bool)
- Suspicious TLD membership (small curated list: .zip, .top, .xyz, .tk, etc.)
- Brand-name keyword present but NOT on the real brand's domain
  (typosquat heuristic — Levenshtein distance to a small known-brand list)
- Presence of URL-shortener domain
- Ratio of digits to letters in hostname
- Count of '//' redirections inside path
- Has suspicious keywords in path/query (login, verify, secure, update, etc.)

Output: a flat `dict` of numeric/bool features, consumed by both the rule
engine (thresholds) and the ML model (as its feature vector).

## 3. Rule Engine (`rules.py`)
A fixed list of independent rule functions, each taking the feature dict
and returning `(fired: bool, evidence: str, severity: "low"|"medium"|"high")`.
Examples:
- IP-as-hostname → high
- Brand keyword + not on brand domain → high
- URL shortener → medium
- No HTTPS → low
- Excess subdomains (>3) → medium
- Suspicious TLD → medium

Final rule-engine verdict = aggregate of fired rule severities into a
0–100 score, independent of the ML model's output. This is what the UI
calls the "Rule-Based Findings" panel.

## 4. ML Model (`model.py`, `models/train.py`)
- Algorithm: `RandomForestClassifier` (good default for tabular/lexical
  features, gives built-in feature_importances_ for explainability, no
  scaling required).
- Train/test split: 80/20, stratified on label.
- Metrics captured at training time: precision, recall, F1, confusion
  matrix — saved to `models/metrics.json` and rendered on the Model
  Evaluation page via Plotly.
- Explainability: for a single prediction, report the top contributing
  features by combining the model's global `feature_importances_` with
  that URL's own feature values (so the UI can say "flagged mainly due to:
  hostname has 5 subdomains, contains '@', uses IP address" etc.)

## 5. Storage (`storage.py`)
SQLite table `assessments`:
`id, timestamp, domain, url_hash (sha256), rule_score, ml_probability,
final_verdict`. The **full raw URL is not persisted** — only domain (for
display) and a hash (for dedup/lookup) — per FR8/PRD §4 privacy goal.

## 6. Report Generation (`report.py`)
ReportLab-based PDF: summary verdict, rule-engine findings table, ML
probability + top contributing features, limitations/disclaimer section
(mirrors PRD §10), generated per-assessment and offered as a Streamlit
download button.

## 7. Dashboard Pages (`main.py`)
1. **Assess URL** — input box, run analysis, show rule findings + ML
   verdict + explanation side by side, download report button.
2. **Model Evaluation** — precision/recall/F1, confusion matrix heatmap,
   feature importance bar chart.
3. **History** — table of past assessments from SQLite, filterable by
   verdict.

## 8. Testing (`tests/`)
Pytest unit tests covering: feature extraction on known tricky URLs
(IP-based, typosquat, shortener), rule engine firing correctly per rule,
model load + predict returns valid probability range.

## 9. Explainability Design Note
"Explainable" in this project means two concrete, inspectable things —
not a vague claim:
1. The rule engine's findings are deterministic and human-readable by
   construction (if X then flagged for Y).
2. The ML model's prediction is paired with the specific feature values
   of *that* URL weighted by global importance — not just a bare
   probability number.
