"""
Integration point between the ML model and the rest of the pipeline.

scanner.keyboard_hook_detector calls score_entry() for each suspect entry it
builds; the result (an ml_risk_score in [0, 1], or None if scoring wasn't
possible) is attached to the entry and later folded into temporal risk
scoring by scanner.temporal_risk_engine.
"""
from scanner.logger_config import setup_logger
from scanner.ml.pe_features import extract_pe_features
from scanner.ml.model import predict_risk_probability

logger = setup_logger(__name__)

_warned_missing_model = False


def score_entry(entry):
    """Return P(malware) in [0, 1] for a suspect entry's executable, or None."""
    global _warned_missing_model
    exe = entry.get("executable")
    if not exe:
        return None

    features = extract_pe_features(exe)
    if features is None:
        logger.debug(f"Could not extract PE features for {exe}; skipping ML scoring")
        return None

    try:
        return predict_risk_probability(features)
    except FileNotFoundError:
        if not _warned_missing_model:
            logger.warning(
                "ML model not found; skipping ML scoring. Run 'python train_model.py' to generate it."
            )
            _warned_missing_model = True
        return None
    except Exception as e:
        logger.debug(f"ML scoring failed for {exe}: {e}")
        return None
