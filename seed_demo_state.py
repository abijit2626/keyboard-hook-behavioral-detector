"""
Write clearly-labeled SAMPLE data to temporal_state.json for presentations.

The dashboard and `python -m scanner.report` only show what main_controller.py
has observed, so on a fresh machine they start empty and a real HIGH-risk
process takes several scan cycles (and something suspicious actually running)
to appear. This script pre-fills the same state file with a handful of
made-up processes so you can show every risk level straight away.

Nothing here is real telemetry: the executables are fictional, and the file is
tagged `"_meta": {"demo": true}` so it can be recognised and removed.

Usage:
    python seed_demo_state.py            # refuses to overwrite real data
    python seed_demo_state.py --clear    # remove demo data again
    python seed_demo_state.py --force    # overwrite whatever is there
"""
import argparse
import json
import os
import sys
import time

from scanner.config import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

STATE_FILE = "temporal_state.json"

# (identity, exe, score, ml_risk_score, keylogger_api_score, matched, event_counts, age_seconds)
_SAMPLES = [
    (
        "svc_updater.exe|4120",
        r"C:\Users\demo\AppData\Local\Temp\svc_updater.exe",
        128, 0.96, 0.81,
        ["low_level_hook", "keystate_polling", "window_tracking", "network_exfiltration"],
        {"SUSPECT_DETECTED": 1, "HOOK_APPEARED": 2, "NEW_HOOK_MODULE": 2},
        45,
    ),
    (
        "clipwatch.exe|7788",
        r"C:\Users\demo\Downloads\clipwatch.exe",
        74, 0.71, 0.55,
        ["keystate_polling", "clipboard_capture", "persistence_registry_run"],
        {"SUSPECT_DETECTED": 1, "NEW_HOOK_MODULE": 1},
        90,
    ),
    (
        "hotkey_helper.exe|3302",
        r"C:\Program Files\HotkeyHelper\hotkey_helper.exe",
        41, 0.22, 0.30,
        ["low_level_hook", "keystate_polling"],
        {"SUSPECT_DETECTED": 2, "HOOK_APPEARED": 1},
        120,
    ),
    (
        "screenrec.exe|5516",
        r"C:\Program Files\ScreenRec\screenrec.exe",
        26, 0.12, 0.34,
        ["screen_capture", "window_tracking"],
        {"SUSPECT_DETECTED": 1},
        200,
    ),
    (
        "notes_app.exe|2204",
        r"C:\Program Files\NotesApp\notes_app.exe",
        11, 0.04, 0.02,
        [],
        {"SUSPECT_DETECTED": 1},
        300,
    ),
    (
        "discord.exe|9012",
        r"C:\Users\demo\AppData\Local\Discord\app-1.0.9\discord.exe",
        0, None, None,
        [],
        {"SUSPECT_DETECTED": 3, "HOOK_APPEARED": 1},
        15,
    ),
]


def _level(score):
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def build_state(now=None):
    now = time.time() if now is None else now
    state = {"_meta": {"last_snapshot": "", "demo": True}}
    for identity, exe, score, ml, kl, matched, counts, age in _SAMPLES:
        entry = {
            "risk_score": score,
            "risk_level": _level(score),
            "event_counts": dict(counts),
            "first_seen": now - age - 600,
            "last_seen": now - age,
            "exe": exe,
        }
        if ml is not None:
            entry["ml_risk_score"] = ml
        if kl is not None:
            entry["keylogger_api_score"] = kl
            entry["keylogger_apis_matched"] = list(matched)
        state[identity] = entry
    return state


def _is_demo(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return bool(json.load(f).get("_meta", {}).get("demo"))
    except (OSError, ValueError, AttributeError):
        return False


def main(argv=None, path=STATE_FILE):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--clear", action="store_true", help="delete demo data")
    parser.add_argument("--force", action="store_true", help="overwrite/delete even real data")
    args = parser.parse_args(argv)

    exists = os.path.exists(path)
    if exists and not args.force and not _is_demo(path):
        print(
            f"{path} already exists and is not demo data -- refusing to touch it.\n"
            "Re-run with --force if you really want to replace it."
        )
        return 1

    if args.clear:
        if exists:
            os.remove(path)
            print(f"Removed {path}.")
        else:
            print(f"Nothing to remove ({path} not found).")
        return 0

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(build_state(), f, indent=2)
    os.replace(tmp, path)
    print(f"Wrote {len(_SAMPLES)} sample processes to {path}.")
    print("Start the dashboard with start_dashboard.bat (or: python -m scanner.dashboard).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
