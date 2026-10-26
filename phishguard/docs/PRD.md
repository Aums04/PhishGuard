# PhishGuard — Product Requirements Document

## 1. Overview
PhishGuard is a web-based tool that assesses whether a submitted URL is likely
phishing or legitimate. It combines a machine-learning classifier with a
deterministic rule engine, and shows both results separately so the user can
see *why* a URL was flagged, not just a label.

## 2. Problem Statement
Blocklists fail on new/unseen phishing URLs. Pure ML classifiers give a
label with no reasoning, which is not good enough for security assessment.
PhishGuard addresses both gaps: ML handles pattern detection on unseen URLs,
the rule engine gives transparent, inspectable evidence.

## 3. Goals / Objectives
1. ML model to classify a URL as phishing / legitimate.
2. Extract lexical + structural URL features.
3. Rule engine that independently flags suspicious characteristics.
4. Explain predictions: show feature importances + which rules fired and why.
5. Evaluate the model with precision, recall, F1, confusion matrix.
6. Interactive dashboard for submitting URLs and viewing results.
7. Downloadable report (PDF) per assessment.
8. Assessment history, stored without the full raw URL where avoidable
   (store a hash + domain only).

## 4. Non-Goals
- Does not visit/render submitted URLs (static analysis only).
- Does not claim certainty — output is a risk score + evidence, not a
  guarantee.
- No real-time blocklist takedown / enforcement action.
- Live domain-reputation API enrichment is optional/stretch, not core.

## 5. Users
- Primary: the student/evaluator demoing the tool.
- Secondary (in spirit): a security analyst triaging a suspicious URL.

## 6. Functional Requirements
| ID | Requirement |
|----|-------------|
| FR1 | User can submit a URL via a text input |
| FR2 | System extracts lexical/structural features from the URL string |
| FR3 | Rule engine evaluates the URL against a fixed rule set, returns matched rules + evidence |
| FR4 | ML model returns a phishing probability + predicted label |
| FR5 | Dashboard shows ML result and rule-engine result as separate panels |
| FR6 | Dashboard shows which features drove the ML prediction (feature importance for the matched instance) |
| FR7 | Model Evaluation page shows precision/recall/F1/confusion matrix on the held-out test set |
| FR8 | Every assessment is saved to history (timestamp, domain, verdict, scores) |
| FR9 | User can download a PDF report for a given assessment |
| FR10 | History view lets the user browse/filter past assessments |

## 7. Non-Functional Requirements
- Static analysis only — no outbound request to the submitted URL.
- Response time: assessment result in under 2 seconds for a single URL.
- Local-only data storage (SQLite), no raw full URL kept longer than needed
  for the session's history entry; store a truncated/hashed form for display.
- Code must be modular: feature extraction, rule engine, and ML model are
  independent, separately testable units.

## 8. Tech Stack
- App/UI: Streamlit
- ML: scikit-learn, pandas
- Visualization: Plotly (embedded in Streamlit)
- Storage: SQLite
- Reports: ReportLab (PDF)
- Testing: Pytest

## 9. Success Criteria
- Model achieves reasonable test-set F1 (documented honestly, not inflated)
  on the curated dataset.
- Every ML verdict is accompanied by rule-engine evidence and feature
  importances — no "black box" output anywhere in the UI.
- App runs end-to-end locally with `streamlit run app/main.py`.

## 10. Risks / Limitations (stated up front, for the report)
- Dataset is a curated/synthetic sample, not a live threat-intel feed —
  model generalization is limited and should be stated as such.
- Static lexical analysis cannot catch phishing pages that are
  lexically clean but visually/behaviorally deceptive (e.g. compromised
  legitimate domains). This is explicitly out of scope.
- Rule thresholds are heuristic, not tuned against a large labeled corpus.
