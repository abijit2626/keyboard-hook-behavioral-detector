import time
import json
import os

from scanner.logger_config import setup_logger
from scanner.config import (
    EVENT_WEIGHTS, RISK_DECAY, RISK_MEDIUM_THRESHOLD, RISK_HIGH_THRESHOLD, ALLOWLIST
)

STATE_FILE = "temporal_state.json"

logger = setup_logger(__name__)


def load_state():
    """Load temporal risk state from file."""
    if not os.path.exists(STATE_FILE):
        logger.debug(f"State file {STATE_FILE} does not exist, returning empty state")
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
            logger.debug(f"Loaded state for {len(state)} process identities")
            return state
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load state from {STATE_FILE}: {e}")
        return {}


def save_state(state):
    """Save temporal risk state to file with locking."""
    temp_file = STATE_FILE + ".tmp"
    
    # Retry mechanism for file operations
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Write to temp file first
            with open(temp_file, "w", encoding="utf-8") as f:
                # Lock file for exclusive write access
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                except (ImportError, AttributeError, OSError):
                    # Fallback: continue without locking if not available
                    logger.warning("File locking not available or failed on this platform")
                
                json.dump(state, f, indent=2)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
                
                # Unlock before closing
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except (ImportError, AttributeError, OSError):
                    pass
            break # Success
        except PermissionError:
             if attempt < max_retries - 1:
                 time.sleep(0.2)
             else:
                 raise

    try:
        # Atomic rename (Windows needs special handling)
        if os.name == 'nt':
            if os.path.exists(STATE_FILE):
                try:
                    os.remove(STATE_FILE)
                except OSError:
                     # If remove fails, it might be locked. Wait and retry.
                     time.sleep(0.2)
                     os.remove(STATE_FILE)
            os.rename(temp_file, STATE_FILE)
        else:
            os.rename(temp_file, STATE_FILE)
            
        logger.debug(f"Saved state for {len(state)} process identities to {STATE_FILE}")
    except IOError as e:
        logger.error(f"Failed to save state to {STATE_FILE} (Step: Write/Rename): {e}")
        # Clean up temp file on error
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        raise


def update_temporal_risk(events):
    """Update risk scores based on temporal events."""
    logger.info(f"Updating temporal risk for {len(events)} events")
    
    state = load_state()
    now = time.time()
    touched = set()

    # --- ingest change events only ---
    last_processed_time = state.get("_meta", {}).get("last_snapshot", "")
    max_event_time = last_processed_time

    filtered_events = []
    for e in events:
        if e["time"] > last_processed_time:
            filtered_events.append(e)
            if e["time"] > max_event_time:
                max_event_time = e["time"]
    
    logger.info(f"Processing {len(filtered_events)} new events (filtered from {len(events)})")

    for e in filtered_events:
        identity = e["identity"]
        etype = e["event"]

        if identity not in state:
            logger.debug(f"New process identity detected: {identity} ({e['exe']})")
            state[identity] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": {},
                "first_seen": now,
                "last_seen": now,
                "exe": e["exe"]
            }

        s = state[identity]
        touched.add(identity)

        old_score = s["risk_score"]
        s["event_counts"][etype] = s["event_counts"].get(etype, 0) + 1
        import os.path
        base = os.path.basename(s["exe"]).lower()
        if base in ALLOWLIST:
            weight = 0
        else:
            weight = EVENT_WEIGHTS.get(etype, 0)
            gated = etype in ("HOOK_APPEARED", "NEW_HOOK_MODULE")
            has_base = s["event_counts"].get("SUSPECT_DETECTED", 0) > 0 or s["risk_score"] > 0
            if gated and not has_base:
                weight = 0
        s["risk_score"] += weight
        s["last_seen"] = now
        
        logger.debug(
            f"Event {etype} for {identity}: "
            f"score {old_score} -> {s['risk_score']} (weight: {weight})"
        )

    # Apply decay and classification to ALL identities
    for identity, s in state.items():
        if identity == "_meta":
            continue
            
        old_level = s["risk_level"]
        
        # Apply standard decay to everyone
        # We assume this function is called once per analysis cycle
        s["risk_score"] = max(0, s["risk_score"] - RISK_DECAY)
        s["last_seen"] = now

        # Update risk level classification
        if s["risk_score"] >= RISK_HIGH_THRESHOLD:
            s["risk_level"] = "HIGH"
        elif s["risk_score"] >= RISK_MEDIUM_THRESHOLD:
            s["risk_level"] = "MEDIUM"
        else:
            s["risk_level"] = "LOW"
        
        # Log level changes
        if old_level != s["risk_level"]:
            logger.warning(
                f"Risk level changed for {identity} ({s['exe']}): "
                f"{old_level} -> {s['risk_level']} (score: {s['risk_score']})"
            )
        elif s["risk_level"] == "HIGH":
            logger.warning(
                f"High risk maintained for {identity} ({s['exe']}): "
                f"score {s['risk_score']}"
            )

    # Update metadata
    if "_meta" not in state:
        state["_meta"] = {}
    state["_meta"]["last_snapshot"] = max_event_time

    save_state(state)
    logger.info(f"Risk update complete: {len(state)} process(es) in state")
    return state


