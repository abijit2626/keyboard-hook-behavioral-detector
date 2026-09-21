import subprocess
import time
import json
import os
import sys

from scanner.temporal_risk_engine import update_temporal_risk
from scanner.logger_config import setup_logger
from scanner.config import SCAN_INTERVAL, ANALYZE_EVERY, SNAPSHOT_RETENTION_COUNT

SCANNER = "scanner.scanner"
ANALYZER = "scanner.temporal_analyzer"
EVENT_FILE = "temporal_events.json"
SNAPSHOT_DIR = "snapshots"

logger = setup_logger(__name__)



def run(module):
    """Run a module as a subprocess and log the results."""
    logger.debug(f"Running module: {module}")
    result = subprocess.run(
        [sys.executable, "-m", module],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    if result.returncode != 0:
        logger.error(f"Module {module} failed with return code {result.returncode}")
        if result.stderr:
            logger.error(f"Error output: {result.stderr}")
    else:
        logger.debug(f"Module {module} completed successfully")
        if result.stdout:
            logger.debug(f"Output: {result.stdout}")
    
    return result


def load_events():
    """Load temporal events from file."""
    if not os.path.exists(EVENT_FILE):
        logger.debug(f"Event file {EVENT_FILE} does not exist, returning empty list")
        return []
    try:
        with open(EVENT_FILE, "r", encoding="utf-8") as f:
            events = json.load(f)
            logger.debug(f"Loaded {len(events)} events from {EVENT_FILE}")
            return events
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load events from {EVENT_FILE}: {e}")
        return []


def clear_events():
    """Clear the temporal events file."""
    try:
        with open(EVENT_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
        logger.debug(f"Cleared events file: {EVENT_FILE}")
    except IOError as e:
        logger.error(f"Failed to clear events file {EVENT_FILE}: {e}")


def prune_snapshots(keep=SNAPSHOT_RETENTION_COUNT):
    """
    Delete all but the `keep` most recent snapshot files.

    Without this, snapshots/ grows without bound on a long-running
    deployment, and temporal_analyzer.py rebuilds identity history from
    every snapshot ever taken on each analysis cycle -- an unbounded,
    ever-slower recompute of state that's already reflected in
    temporal_state.json. Once a snapshot's events have been folded into
    the persistent risk state, the raw snapshot isn't needed anymore
    except as a diff baseline for the next cycle.
    """
    if not os.path.isdir(SNAPSHOT_DIR):
        return
    try:
        files = sorted(
            f for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json")
        )
    except OSError as e:
        logger.warning(f"Failed to list {SNAPSHOT_DIR} for pruning: {e}")
        return

    stale = files[:-keep] if keep > 0 else files
    for f in stale:
        try:
            os.remove(os.path.join(SNAPSHOT_DIR, f))
        except OSError as e:
            logger.warning(f"Failed to prune snapshot {f}: {e}")

    if stale:
        logger.debug(f"Pruned {len(stale)} old snapshot(s), kept {len(files) - len(stale)}")


def main():
    """Main controller loop for periodic scanning and analysis."""
    logger.info("Starting keylogger detection controller")
    logger.info(f"Scan interval: {SCAN_INTERVAL}s, Analyze every: {ANALYZE_EVERY} scans")
    
    count = 0
    try:
        while True:
            logger.info(f"Starting scan cycle #{count + 1}")
            run(SCANNER)
            count += 1

            if count % ANALYZE_EVERY == 0:
                logger.info(f"Running temporal analysis (every {ANALYZE_EVERY} scans)")
                run(ANALYZER)
                events = load_events()
                if events:
                    logger.info(f"Processing {len(events)} temporal events")
                    state = update_temporal_risk(events)
                    clear_events()
                    prune_snapshots()

                    high_risk_count = 0
                    for ident, s in state.items():
                        if ident == "_meta":
                            continue
                        if s.get("risk_level") == "HIGH":
                            high_risk_count += 1
                            logger.critical(
                                f"HIGH RISK DETECTED - Identity: {ident}, "
                                f"Executable: {s['exe']}, Risk Score: {s['risk_score']}"
                            )
                    
                    if high_risk_count > 0:
                        logger.warning(f"Found {high_risk_count} process(es) with HIGH risk level")
                    else:
                        logger.debug("No high-risk processes detected in this cycle")

            logger.debug(f"Sleeping for {SCAN_INTERVAL} seconds until next scan")
            time.sleep(SCAN_INTERVAL)
    
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down gracefully")
    except Exception as e:
        logger.critical(f"Unexpected error in main loop: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
