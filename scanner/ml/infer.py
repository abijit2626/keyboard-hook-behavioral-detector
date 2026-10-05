"""
Standalone inference: score executables on disk with both ML/heuristic
layers, without needing Windows or the scan loop.

The live pipeline only ever scores executables belonging to running
processes it flags as hook-capable (scanner/keyboard_hook_detector.py,
Windows only). This is the same scoring -- scanner.ml.analysis.analyze_executable,
so one PE parse feeding both layers, results identical to what the scanner
would record -- pointed at files or directories you choose, on any OS.
Static analysis only: files are parsed, never executed.

    malware ML     scanner/ml/model.py -- RandomForest trained on the real
                   ClaMP dataset; P(this PE's structure looks like malware).
    keylogger API  scanner/ml/keylogger_signatures.py -- weighted import-table
                   fingerprint mapped to MITRE ATT&CK; 0-1.

These are risk signals, not verdicts (see README: Design Philosophy) --
capability does not imply malicious intent.

Usage:
    python -m scanner.ml.infer path/to/file.exe
    python -m scanner.ml.infer C:\\Some\\Folder other.dll
    python -m scanner.ml.infer samples/ --json

Directories are searched recursively for PE-looking files (PE_EXTENSIONS).
A file named explicitly is always scored, whatever its extension.

Exit status: 0 if at least one file was scored and nothing went wrong,
1 if any path was missing / not a parsable PE, or the model isn't trained.
"""
import argparse
import json
import os
import sys

from scanner.ml.analysis import analyze_executable
from scanner.ml.model import MODEL_PATH

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}


def collect_targets(paths):
    """
    Expand `paths` into (files, missing). Directories are walked
    recursively for PE_EXTENSIONS files; plain files pass through as-is.
    Order is stable and duplicates are dropped.
    """
    files, missing, seen = [], [], set()

    def add(path):
        key = os.path.abspath(path)
        if key not in seen:
            seen.add(key)
            files.append(path)

    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs.sort()
                for name in sorted(names):
                    if os.path.splitext(name)[1].lower() in PE_EXTENSIONS:
                        add(os.path.join(root, name))
        elif os.path.isfile(path):
            add(path)
        else:
            missing.append(path)
    return files, missing


def infer_file(path):
    """
    Score one file. Returns the analyze_executable() dict plus "path" and
    "scored" (False when neither layer could read it -- not a parsable PE).
    """
    result = dict(analyze_executable(path))
    result["path"] = path
    result["scored"] = (
        result["ml_risk_score"] is not None
        or result["keylogger_api_score"] is not None
    )
    return result


def _fmt_pct(value):
    return f"{value * 100:.0f}%" if value is not None else "-"


def render_table(results, out=None):
    """Print results as a table, highest malware-ML score first."""
    out = out or sys.stdout  # resolved per call so redirected stdout is honored
    scored = [r for r in results if r["scored"]]
    scored.sort(key=lambda r: -(r["ml_risk_score"] or 0))

    headers = ["MALWARE ML", "KEYLOGGER API", "ATT&CK", "EXECUTABLE"]
    table = [
        [
            _fmt_pct(r["ml_risk_score"]),
            _fmt_pct(r["keylogger_api_score"]),
            ", ".join(r["keylogger_apis_matched"]) or "-",
            r["path"],
        ]
        for r in scored
    ]
    if table:
        widths = [
            max(len(headers[i]), max(len(row[i]) for row in table))
            for i in range(len(headers))
        ]

        def print_row(cells):
            print("  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip(), file=out)

        print_row(headers)
        print_row(["-" * w for w in widths])
        for row in table:
            print_row(row)

    skipped = [r["path"] for r in results if not r["scored"]]
    for path in skipped:
        print(f"skipped (not a parsable PE file): {path}", file=out)
    print(f"\n{len(scored)} scored, {len(skipped)} skipped.", file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m scanner.ml.infer",
        description="Score executables with the malware-ML and keylogger-API "
                    "layers (static analysis; files are never executed).",
    )
    parser.add_argument("paths", nargs="+", help="PE files and/or directories to scan")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of a table")
    args = parser.parse_args(argv)

    if not os.path.exists(MODEL_PATH):
        print(f"error: ML model not found at {MODEL_PATH}. "
              "Run 'python train_model.py' first.", file=sys.stderr)
        return 1

    files, missing = collect_targets(args.paths)
    for path in missing:
        print(f"error: no such file or directory: {path}", file=sys.stderr)

    results = [infer_file(path) for path in files]

    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    elif results:
        render_table(results)
    elif not missing:
        print("No PE files found.")

    ok = bool(results) and all(r["scored"] for r in results) and not missing
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
