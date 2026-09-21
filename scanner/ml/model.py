"""
Loading and inference for the trained ML risk model.

Training happens offline via train_model.py; this module only loads the
resulting artifact and scores feature vectors at scan time.
"""
import os

import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), "artifacts", "clamp_pe_model.joblib")

_model_cache = None


def load_model():
    """Load (and cache) the trained model from MODEL_PATH."""
    global _model_cache
    if _model_cache is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"ML model not found at {MODEL_PATH}. Run 'python train_model.py' first."
            )
        _model_cache = joblib.load(MODEL_PATH)
    return _model_cache


def predict_risk_probability(feature_vector):
    """Return P(suspicious) in [0, 1] for a single feature vector."""
    model = load_model()
    proba = model.predict_proba([feature_vector])[0]
    classes = list(model.classes_)
    idx = classes.index(1)
    return float(proba[idx])
