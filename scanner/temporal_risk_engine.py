import time
import json
import os

from scanner.logger_config import setup_logger

STATE_FILE = "temporal_state.json"

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 10,     # weak-to-medium signal
    "NEW_HOOK_MODULE": 35,   # strong signal
    "HOOK_REMOVED": -10     # relief
}

DECAY = 3
MEDIUM = 30
HIGH = 60

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
            except (ImportError, AttributeError):
                # Fallback: continue without locking if not available
                logger.warning("File locking not available on this platform")
            
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
            except (ImportError, AttributeError):
                pass
        
        # Atomic rename (Windows needs special handling)
        if os.name == 'nt':
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
            os.rename(temp_file, STATE_FILE)
        else:
            os.rename(temp_file, STATE_FILE)
            
        logger.debug(f"Saved state for {len(state)} process identities to {STATE_FILE}")
    except IOError as e:
        logger.error(f"Failed to save state to {STATE_FILE}: {e}")
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
    for e in events:
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
        weight = EVENT_WEIGHTS.get(etype, 0)
        s["risk_score"] += weight
        s["last_seen"] = now
        
        logger.debug(
            f"Event {etype} for {identity}: "
            f"score {old_score} -> {s['risk_score']} (weight: {weight})"
        )

    # Apply decay and classification to ALL identities
    for identity, s in state.items():
        old_level = s["risk_level"]
        
        if identity in touched:
            # Already updated with new events, apply standard decay
            s["risk_score"] = max(0, s["risk_score"] - DECAY)
        else:
            # Apply time-based decay for identities not seen in this cycle
            last_seen = s.get("last_seen", s.get("first_seen", now))
            time_since_seen = now - last_seen
            
            # Decay every DECAY seconds (calculate how many decay intervals passed)
            if time_since_seen > DECAY:
                decay_intervals = int(time_since_seen / DECAY)
                s["risk_score"] = max(0, s["risk_score"] - (DECAY * decay_intervals))
            
            # Update last_seen to prevent excessive decay in next cycle
            s["last_seen"] = now

        # Update risk level classification
        if s["risk_score"] >= HIGH:
            s["risk_level"] = "HIGH"
        elif s["risk_score"] >= MEDIUM:
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

    save_state(state)
    logger.info(f"Risk update complete: {len(state)} process(es) in state")
    return state


