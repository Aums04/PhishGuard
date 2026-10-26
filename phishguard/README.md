# PhishGuard

Explainable phishing URL detection — combines a machine-learning classifier
with an independent, deterministic rule engine, and shows both results
separately so a user can see *why* a URL was flagged.

Static analysis only: the app never visits or renders a submitted URL.

## Project docs
- `docs/PRD.md` — product requirements
- `docs/TECHNICAL_DESIGN.md` — architecture and module design

## Setup

```bash
pip install -r requirements.txt
```

## 1. Generate the dataset (already included, re-run if you want new data)

```bash
python3 data/generate_dataset.py
```

## 2. Train the model (already trained, re-run after changing features/dataset)

```bash
python3 models/train.py
```

## 3. Run the tests

```bash
python3 -m pytest tests/ -v
```

## 4. Run the app

```bash
streamlit run app/main.py
```

Then open the local URL Streamlit prints (usually http://localhost:8501).

## Project structure

```
phishguard/
├── app/            # Streamlit UI + all logic modules
├── data/           # dataset + SQLite history DB (generated)
├── models/         # training script + saved model/metrics
├── tests/          # pytest unit tests
├── docs/           # PRD and technical design
└── requirements.txt
```

## Known limitations (see PRD §10 for full list)
- Training data is a curated/synthetic academic dataset, not a live
  threat-intelligence feed — reported precision/recall/F1 reflect a
  clearly separable synthetic dataset, not real-world generalization.
- Static lexical analysis only — cannot detect phishing on a
  lexically-clean but compromised legitimate domain.
