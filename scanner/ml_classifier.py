"""
Integration point between the ML model and the rest of the pipeline.

scanner.keyboard_hook_detector calls score_entry() for each suspect entry it
builds; the result (an ml_risk_score in [0, 1], or None if the model isn't
trained yet) is attached to the entry and later folded into temporal risk
scoring by scanner.temporal_risk_engine.
"""
from scanner.logger_config import setup_logger
from scanner.ml.features import extract_features
from scanner.ml.model import predict_risk_probability

logger = setup_logger(__name__)

_warned_missing_model = False


def score_entry(entry):
    """Return P(suspicious) in [0, 1] for a suspect entry, or None on failure."""
    global _warned_missing_model
    try:
        features = extract_features(entry)
        return predict_risk_probability(features)
    except FileNotFoundError:
        if not _warned_missing_model:
            logger.warning(
                "ML model not found; skipping ML scoring. Run 'python train_model.py' to generate it."
            )
            _warned_missing_model = True
        return None
    except Exception as e:
        logger.debug(f"ML scoring failed for {entry.get('executable')}: {e}")
        return None
