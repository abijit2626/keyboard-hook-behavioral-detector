import time
import json
import os

STATE_FILE = "temporal_state.json"

# ===================== CONFIG =====================

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 8,        # weak evidence
    "NEW_HOOK_MODULE": 30,     # strong evidence
    "HOOK_REMOVED": -5,        # weak relief
    "HOOK_PERSISTED": 0        # CONTEXT ONLY (never risk)
}

DECAY_PER_UPDATE = 2

ESCALATE_MEDIUM = 30
ESCALATE_HIGH = 60

# ===================== STATE HELPERS =====================

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

# ===================== CORE ENGINE =====================

def update_temporal_risk(events):
    """
    Update temporal risk state based on behavioral events.

    Design principles:
    - Persistence is context, never evidence
    - Only behavioral change increases risk
    - Decay applies once per update, not per event
    """

    state = load_state()
    now = time.time()

    # Track which PIDs were updated this cycle
    touched_pids = set()

    # ---------- process events ----------
    for event in events:
        pid = str(event["pid"])
        etype = event["event"]

        if pid not in state:
            state[pid] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": {},
                "first_seen": now,
                "last_seen": now
            }

        entry = state[pid]
        touched_pids.add(pid)

        # Update counters (JSON-safe)
        entry["event_counts"][etype] = entry["event_counts"].get(etype, 0) + 1
        entry["last_seen"] = now

        # Apply event weight (persistence has zero weight)
        entry["risk_score"] += EVENT_WEIGHTS.get(etype, 0)

        # Persistence amplifier (confidence, not suspicion)
        has_persistence = entry["event_counts"].get("HOOK_PERSISTED", 0) >= 2
        has_real_signal = (
            entry["event_counts"].get("HOOK_APPEARED", 0) > 0 or
            entry["event_counts"].get("NEW_HOOK_MODULE", 0) > 0
        )

        if has_persistence and has_real_signal:
            entry["risk_score"] += 5

    # ---------- apply decay & classify ----------
    for pid in touched_pids:
        entry = state[pid]

        # Apply decay once per update
        entry["risk_score"] = max(
            0,
            entry["risk_score"] - DECAY_PER_UPDATE
        )

        # Assign risk level
        if entry["risk_score"] >= ESCALATE_HIGH:
            entry["risk_level"] = "HIGH"
        elif entry["risk_score"] >= ESCALATE_MEDIUM:
            entry["risk_level"] = "MEDIUM"
        else:
            entry["risk_level"] = "LOW"

    save_state(state)
    return state
