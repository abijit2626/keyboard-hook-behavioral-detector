"""
Train the ML risk-scoring model used by the keyboard hook detector.

Usage:
    python train_model.py

Trains a RandomForestClassifier on ClaMP (github.com/urwithajit9/ClaMP), a
real dataset of PE header features extracted from 5,210 actual Windows
executables (2,722 malware + 2,488 benign) -- see scanner/ml/dataset.py
for provenance and scanner/ml/pe_features.py for the matching live feature
extractor. Prints evaluation metrics and saves the model to
scanner/ml/artifacts/clamp_pe_model.joblib for scanner.ml_classifier to
load at scan time.
"""
import os

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from scanner.ml.dataset import load_dataset
from scanner.ml.pe_features import FEATURE_NAMES
from scanner.ml.model import MODEL_PATH


def main():
    X, y = load_dataset()
    print(f"Loaded {len(X)} real samples ({sum(y)} malware, {len(y) - sum(y)} benign)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2, random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["benign", "malware"]))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, y_pred))

    print("\nTop 15 feature importances:")
    for name, importance in sorted(
        zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]
    )[:15]:
        print(f"  {name}: {importance:.4f}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
