import os
import json
from datetime import datetime, UTC

from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects
from scanner.logger_config import setup_logger

logger = setup_logger(__name__)


def main():
    """Perform a single scan cycle and save snapshot."""
    if os.name != "nt":
        logger.error("Windows only.")
        return

    logger.info("Starting keyboard hook detection scan")

    try:
        os.makedirs("snapshots", exist_ok=True)
        logger.debug("Snapshots directory ready")

        logger.debug("Detecting keyboard hook suspects...")
        suspects = detect_keyboard_hook_suspects()
        logger.info(f"Detected {len(suspects)} keyboard hook suspect(s)")

        result = {
            "timestamp": datetime.now(UTC).isoformat(),
            "keyboard_hook_suspects": suspects
        }

        fname = f"snapshots/scan_{result['timestamp'].replace(':','-')}.json"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Snapshot written: {fname}")
            logger.debug(f"Snapshot contains {len(suspects)} suspect entries")
        except IOError as e:
            logger.error(f"Failed to write snapshot to {fname}: {e}")
            raise
    
    except Exception as e:
        logger.error(f"Error during scan cycle: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
