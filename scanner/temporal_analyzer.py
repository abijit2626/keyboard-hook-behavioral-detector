import os
import json
from collections import defaultdict

SNAPSHOT_DIR = "snapshots"
OUTPUT_FILE = "temporal_events.json"

print("[DEBUG] TEMPORAL ANALYZER FILE:", __file__)

def load_snapshots():
    files = sorted(f for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json"))
    snapshots = []
    for f in files:
        with open(os.path.join(SNAPSHOT_DIR, f), "r", encoding="utf-8") as fp:
            snapshots.append({"time": f, "data": json.load(fp)})
    return snapshots


def build_identity(entry):
    return f"{entry['executable']}|{entry['create_time']}"


def analyze():
    snaps = load_snapshots()
    if len(snaps) < 2:
        print("[!] Need at least 2 snapshots")
        return

    history = defaultdict(list)

    # Build identity timelines
    for snap in snaps:
        for e in snap["data"].get("keyboard_hook_suspects", []):
            if "create_time" not in e:
                continue

            identity = build_identity(e)
            history[identity].append({
                "time": snap["time"],
                "pid": e["pid"],
                "exe": e["executable"],
                "dlls": {m["dll"] for m in e.get("suspicious_modules", [])}
            })

    events = []

    # Emit ONLY change events
    for identity, records in history.items():
        for i in range(1, len(records)):
            prev, curr = records[i - 1], records[i]

            # First appearance of hook capability
            if not prev["dlls"] and curr["dlls"]:
                events.append({
                    "event": "HOOK_APPEARED",
                    "identity": identity,
                    "exe": curr["exe"],
                    "pid": curr["pid"],
                    "time": curr["time"]
                })

            # New hook carrier introduced
            new = curr["dlls"] - prev["dlls"]
            if new:
                events.append({
                    "event": "NEW_HOOK_MODULE",
                    "identity": identity,
                    "exe": curr["exe"],
                    "pid": curr["pid"],
                    "time": curr["time"]
                })

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

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[+] Temporal events written: {OUTPUT_FILE}")


if __name__ == "__main__":
    analyze()
