import os
import json
from collections import defaultdict

from scanner.logger_config import setup_logger

SNAPSHOT_DIR = "snapshots"
OUTPUT_FILE = "temporal_events.json"

logger = setup_logger(__name__)


def load_snapshots():
    """Load all snapshot files from the snapshots directory."""
    try:
        if not os.path.exists(SNAPSHOT_DIR):
            logger.warning(f"Snapshot directory {SNAPSHOT_DIR} does not exist")
            return []
        
        files = [f for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json")]
        logger.debug(f"Found {len(files)} snapshot file(s)")
        
        snapshots = []
        for f in files:
            try:
                filepath = os.path.join(SNAPSHOT_DIR, f)
                with open(filepath, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    
                    # Parse timestamp from JSON data
                    timestamp_str = data.get("timestamp", "")
                    timestamp_value = None
                    try:
                        from datetime import datetime
                        # Handle both ISO format with and without Z suffix
                        timestamp_str_clean = timestamp_str.replace('Z', '+00:00')
                        timestamp = datetime.fromisoformat(timestamp_str_clean)
                        timestamp_value = timestamp.timestamp()
                    except (ValueError, AttributeError, TypeError):
                        # Fallback to file modification time
                        timestamp_value = os.path.getmtime(filepath)
                        logger.debug(f"Using file mtime for snapshot {f} (failed to parse timestamp)")
                    
                    snapshots.append({
                        "time": f,
                        "timestamp": timestamp_value,
                        "data": data
                    })
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load snapshot {f}: {e}")
                continue
        
        # Sort by actual timestamp value, not filename
        snapshots.sort(key=lambda x: x["timestamp"])
        
        # Return in original format (without timestamp key)
        return [{"time": s["time"], "data": s["data"]} for s in snapshots]
    except Exception as e:
        logger.error(f"Error loading snapshots: {e}", exc_info=True)
        return []


def build_identity(entry):
    return f"{entry['executable']}|{entry['create_time']}"


def analyze():
    """Analyze snapshots and generate temporal events."""
    logger.info("Starting temporal analysis")
    
    snaps = load_snapshots()
    if len(snaps) < 2:
        logger.warning(f"Need at least 2 snapshots for analysis, found {len(snaps)}")
        return

    logger.debug(f"Analyzing {len(snaps)} snapshots")
    history = defaultdict(list)

    # Build identity timelines
    for snap in snaps:
        suspects = snap["data"].get("keyboard_hook_suspects", [])
        logger.debug(f"Processing snapshot {snap['time']} with {len(suspects)} suspects")
        
        for e in suspects:
            if "create_time" not in e:
                logger.debug(f"Skipping entry without create_time: {e.get('executable', 'unknown')}")
                continue

            identity = build_identity(e)
            history[identity].append({
                "time": snap["time"],
                "pid": e["pid"],
                "exe": e["executable"],
                "dlls": {m["dll"] for m in e.get("suspicious_modules", [])}
            })

    logger.debug(f"Built history for {len(history)} unique process identities")
    events = []

    # Emit ONLY behavioral changes
    for identity, records in history.items():
        for i in range(1, len(records)):
            prev, curr = records[i - 1], records[i]

            # Hook capability appears
            if not prev["dlls"] and curr["dlls"]:
                events.append({
                    "event": "HOOK_APPEARED",
                    "identity": identity,
                    "exe": curr["exe"],
                    "pid": curr["pid"],
                    "time": curr["time"]
                })
                logger.info(f"HOOK_APPEARED: {curr['exe']} (PID: {curr['pid']})")

            # New hook carrier added
            new = curr["dlls"] - prev["dlls"]
            if new:
                events.append({
                    "event": "NEW_HOOK_MODULE",
                    "identity": identity,
                    "exe": curr["exe"],
                    "pid": curr["pid"],
                    "time": curr["time"]
                })
                logger.warning(f"NEW_HOOK_MODULE: {curr['exe']} (PID: {curr['pid']}), DLLs: {new}")

            # Hook capability removed
            removed = prev["dlls"] - curr["dlls"]
            if removed:
                events.append({
                    "event": "HOOK_REMOVED",
                    "identity": identity,
                    "exe": curr["exe"],
                    "pid": curr["pid"],
                    "time": curr["time"]
                })
                logger.info(f"HOOK_REMOVED: {curr['exe']} (PID: {curr['pid']})")

    try:
        temp_file = OUTPUT_FILE + ".tmp"
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
                logger.warning("File locking not available on this platform")
            
            json.dump(events, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
            
            # Unlock
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except (ImportError, AttributeError):
                pass
        
        # Atomic rename
        if os.name == 'nt':
            if os.path.exists(OUTPUT_FILE):
                os.remove(OUTPUT_FILE)
            os.rename(temp_file, OUTPUT_FILE)
        else:
            os.rename(temp_file, OUTPUT_FILE)
            
        logger.info(f"Temporal events written: {OUTPUT_FILE} ({len(events)} events)")
    except IOError as e:
        logger.error(f"Failed to write temporal events to {OUTPUT_FILE}: {e}")
        temp_file = OUTPUT_FILE + ".tmp"
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        raise


if __name__ == "__main__":
    analyze()

