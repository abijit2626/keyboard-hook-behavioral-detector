"""
Train the ML risk-scoring model used by the keyboard hook detector.

Usage:
    python train_model.py

Trains a RandomForestClassifier on the synthetic behavioral dataset in
scanner/ml/dataset.py, prints evaluation metrics, and saves the model to
scanner/ml/artifacts/hook_risk_model.joblib for scanner.ml_classifier to
load at scan time.
"""
import os

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from scanner.ml.dataset import generate_synthetic_dataset
from scanner.ml.features import FEATURE_NAMES
from scanner.ml.model import MODEL_PATH


def main():
    X, y = generate_synthetic_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=200, max_depth=6, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["benign", "suspicious"]))

    print("Feature importances:")
    for name, importance in sorted(
        zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]
    ):
        print(f"  {name}: {importance:.4f}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
