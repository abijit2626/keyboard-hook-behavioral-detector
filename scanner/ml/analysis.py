"""
Single entry point for scoring one executable with both ML/heuristic
layers -- the malware-ML classifier (scanner/ml/pe_features.py +
scanner/ml/model.py) and the keylogger API fingerprint
(scanner/ml/keylogger_signatures.py).

Both need the same PE file parsed; before this module they each opened
and parsed it independently (two pefile.PE() parses of the same bytes
per suspect, per scan cycle). This opens and parses it exactly once and
hands the same `pe` object to both.

Results are also cached per executable path (functools.lru_cache,
matching the same convention scanner/win_authenticode.py and
scanner/keyboard_hook_detector.py's sha256() already use) -- a process
that's still running on the next scan cycle has the same executable on
disk, so there's no reason to re-parse and re-score it from scratch
every SCAN_INTERVAL seconds.
"""
from functools import lru_cache

import pefile

from scanner.logger_config import setup_logger
from scanner.ml.keylogger_signatures import score_from_pe
from scanner.ml.model import predict_risk_probability
from scanner.ml.pe_features import extract_features_from_pe

logger = setup_logger(__name__)

_warned_missing_model = False


@lru_cache(maxsize=1024)
def analyze_executable(filepath):
    """
    Score `filepath` with both ML/heuristic layers.

    Returns a dict:
        {
            "ml_risk_score": float | None,
            "keylogger_api_score": float | None,
            "keylogger_apis_matched": [str, ...],
        }
    None values mean that layer couldn't be computed (unparsable file,
    model not yet trained, ...) -- callers already treat None as "skip".
    """
    global _warned_missing_model
    result = {
        "ml_risk_score": None,
        "keylogger_api_score": None,
        "keylogger_apis_matched": [],
    }

    try:
        pe = pefile.PE(filepath, fast_load=True)
    except Exception as e:
        logger.debug(f"Could not open {filepath} as a PE file: {e}")
        return result

    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])

        features = extract_features_from_pe(pe, filepath)
        if features is not None:
            try:
                result["ml_risk_score"] = predict_risk_probability(features)
            except FileNotFoundError:
                if not _warned_missing_model:
                    logger.warning(
                        "ML model not found; skipping ML scoring. "
                        "Run 'python train_model.py' to generate it."
                    )
                    _warned_missing_model = True
            except Exception as e:
                logger.debug(f"ML scoring failed for {filepath}: {e}")

        signals = score_from_pe(pe)
        if signals is not None:
            result["keylogger_api_score"] = signals["score"]
            result["keylogger_apis_matched"] = [
                cat["name"] for cat in signals["matched_categories"]
            ]
    except Exception as e:
        logger.debug(f"PE analysis failed for {filepath}: {e}")
    finally:
        pe.close()

    return result
