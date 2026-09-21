"""
Local web dashboard for the keyboard hook detector's risk state.

Reads the same temporal_state.json that scanner/report.py reads -- this
is a read-only view, it never touches the scanner/analyzer/risk-engine
pipeline. Run alongside main_controller.py:

    python main_controller.py      # (Windows) does the actual scanning
    python -m scanner.dashboard    # (any OS) serves the dashboard

Binds to 127.0.0.1 by default -- deliberately local-only. This tool's
own telemetry (which processes look suspicious, on which machine) is
itself sensitive; don't put it on the network without thinking about who
else can reach it. Pass --host 0.0.0.0 to opt into that explicitly.
"""
import argparse
import json
import os
import time

from flask import Flask, jsonify, render_template

STATE_FILE = "temporal_state.json"

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(_BASE_DIR, "templates"),
    static_folder=os.path.join(_BASE_DIR, "static"),
)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def build_payload():
    """Shape temporal_state.json into the JSON the dashboard renders."""
    state = load_state()
    processes = []
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for identity, s in state.items():
        if identity == "_meta":
            continue
        level = s.get("risk_level", "LOW")
        counts[level] = counts.get(level, 0) + 1
        processes.append({
            "identity": identity,
            "exe": s.get("exe", "-"),
            "risk_level": level,
            "risk_score": s.get("risk_score", 0),
            "ml_risk_score": s.get("ml_risk_score"),
            "keylogger_api_score": s.get("keylogger_api_score"),
            "keylogger_apis_matched": s.get("keylogger_apis_matched") or [],
            "event_counts": s.get("event_counts", {}),
            "first_seen": s.get("first_seen"),
            "last_seen": s.get("last_seen"),
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    processes.sort(key=lambda p: (order.get(p["risk_level"], 9), -p["risk_score"]))

    return {
        "generated_at": time.time(),
        "state_file_found": os.path.exists(STATE_FILE),
        "summary": {
            "total": len(processes),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
        },
        "processes": processes,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    return jsonify(build_payload())


def main():
    parser = argparse.ArgumentParser(
        description="Web dashboard for the keyboard hook detector's risk state."
    )
    parser.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (local-only)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
