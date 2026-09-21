"""
Human-readable risk report.

Reads the persistent state main_controller.py maintains (temporal_state.json)
and prints a formatted table -- process, current risk level/score, and the
two independent ML/heuristic signals contributing to it (see README.md,
"Machine Learning Component"):

  ML malware %   scanner/ml -- RandomForestClassifier trained on the real
                 ClaMP dataset; "does this executable's PE structure look
                 like malware in general."

  Keylogger API  scanner/ml/keylogger_signatures.py -- static import-table
                 fingerprint mapped to MITRE ATT&CK T1056.001 and related
                 techniques; "does this import table look like input
                 capture specifically."

Usage:
    python -m scanner.report
"""
import json
import os
import sys

STATE_FILE = "temporal_state.json"

_LEVEL_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _fmt_pct(value):
    return f"{value * 100:.0f}%" if value is not None else "-"


def render(state):
    rows = []
    for identity, s in state.items():
        if identity == "_meta":
            continue
        rows.append(s)

    if not rows:
        print("No process risk data yet -- run main_controller.py for a few cycles first.")
        return

    rows.sort(key=lambda s: (_LEVEL_ORDER.get(s.get("risk_level"), 9), -s.get("risk_score", 0)))

    headers = ["RISK", "SCORE", "MALWARE ML", "KEYLOGGER API", "ATT&CK", "EXECUTABLE"]
    table = []
    for s in rows:
        techniques = sorted({
            cat for cat in (s.get("keylogger_apis_matched") or [])
        })
        table.append([
            s.get("risk_level", "-"),
            str(s.get("risk_score", 0)),
            _fmt_pct(s.get("ml_risk_score")),
            _fmt_pct(s.get("keylogger_api_score")),
            ", ".join(techniques) if techniques else "-",
            s.get("exe", "-"),
        ])

    widths = [
        max(len(headers[i]), max((len(row[i]) for row in table), default=0))
        for i in range(len(headers))
    ]

    def print_row(cells):
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)))

    print_row(headers)
    print_row(["-" * w for w in widths])
    for row in table:
        print_row(row)

    high = sum(1 for s in rows if s.get("risk_level") == "HIGH")
    medium = sum(1 for s in rows if s.get("risk_level") == "MEDIUM")
    print(f"\n{len(rows)} process(es) tracked -- {high} HIGH, {medium} MEDIUM.")


def main():
    render(load_state())


if __name__ == "__main__":
    sys.exit(main())
