"""Trains the PhishGuard RandomForest model on the curated dataset.
Run from project root: python3 models/train.py
"""
import sys
import os
import json
import pickle

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, classification_report

from app.features import extract_features, FEATURE_COLUMNS

HERE = os.path.dirname(__file__)
DATA_PATH = os.path.join(HERE, "..", "data", "urls_dataset.csv")
MODEL_PATH = os.path.join(HERE, "phishguard_model.pkl")
METRICS_PATH = os.path.join(HERE, "metrics.json")


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = [extract_features(u) for u in df["url"]]
    feat_df = pd.DataFrame(rows)
    return feat_df[FEATURE_COLUMNS]


def main():
    df = pd.read_csv(DATA_PATH)
    X = build_feature_matrix(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=10, random_state=42, class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True)

    importances = dict(zip(FEATURE_COLUMNS, clf.feature_importances_.tolist()))

    metrics = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": cm,
        "confusion_matrix_labels": ["Legitimate", "Phishing"],
        "classification_report": report,
        "feature_importances": importances,
        "train_size": len(X_train),
        "test_size": len(X_test),
    }

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f}")
    print(f"Confusion matrix (rows=actual, cols=predicted) [Legit, Phishing]: {cm}")
    print(f"Model saved to {MODEL_PATH}")
    print(f"Metrics saved to {METRICS_PATH}")


if __name__ == "__main__":
    main()
