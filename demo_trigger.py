"""
Harmless Windows demo process that gives the live scanner something to flag.

This does NOT hook the keyboard, read keystrokes, inject code or touch any
other process. It only imitates the *pattern* the detector's temporal engine
reacts to, using nothing but DLLs that ship with your own Python install:

  1. loads user32.dll, so the scanner lists this process as a suspect
     (scanner/keyboard_hook_detector.py requires user32 in the process);
  2. waits long enough for the monitor to snapshot the process as a baseline;
  3. then loads one extra, non-Windows DLL every few seconds. Each one shows
     up in the next snapshot as a NEW_HOOK_MODULE event (35 points each, plus
     the ML bonuses), so the risk score climbs the way it would for a real
     process that keeps pulling in new third-party modules.

Usage (Windows, with the monitor already running in another window):

    .venv\\Scripts\\python demo_trigger.py
    .venv\\Scripts\\python demo_trigger.py --delay 40 --interval 12 --count 6

Press Ctrl+C to stop; the process exiting is what lets the score decay again.
Each run is a new process, so it appears as a new row in the dashboard.
"""
import argparse
import os
import sys
import time

from scanner.config import WINDOWS_DIR


def find_candidate_dlls(base_prefix, loaded_paths, windows_dir=WINDOWS_DIR):
    """
    DLLs shipped with the Python install that aren't loaded yet.

    Looks in the install root and its DLLs/ folder. Anything already mapped
    into this process (compared case-insensitively) or under the Windows
    directory is excluded, because the detector ignores the latter and the
    former wouldn't be a *new* module.
    """
    loaded = {p.lower() for p in loaded_paths}
    found = []
    for folder in (base_prefix, os.path.join(base_prefix, "DLLs")):
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for name in names:
            if not name.lower().endswith(".dll"):
                continue
            path = os.path.join(folder, name)
            lowered = path.lower()
            if lowered in loaded or lowered.startswith(windows_dir.lower()):
                continue
            found.append(path)
    return found


def _loaded_dll_paths():
    import psutil
    try:
        return [m.path for m in psutil.Process().memory_maps() if m.path]
    except (psutil.Error, OSError):
        return []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--delay", type=float, default=25,
                        help="seconds to wait before the first load so the monitor sees a "
                             "baseline snapshot first (scan interval is 10s; default 25)")
    parser.add_argument("--interval", type=float, default=12,
                        help="seconds between loads; keep it above the scan interval "
                             "so each load lands in a different snapshot (default 12)")
    parser.add_argument("--count", type=int, default=6, help="how many DLLs to load (default 6)")
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("The live scanner is Windows-only, so this demo does nothing elsewhere.")
        return 1

    import ctypes
    ctypes.WinDLL("user32")  # makes this process a scanner suspect

    print(f"demo_trigger running as PID {os.getpid()} ({sys.executable})")
    print("Make sure start_monitor.bat is running in another window.")
    print(f"Waiting {args.delay:.0f}s so the monitor records a baseline ...", flush=True)

    keep_alive = []  # references so the loaded DLLs stay mapped
    try:
        time.sleep(args.delay)
        candidates = find_candidate_dlls(sys.base_prefix, _loaded_dll_paths())
        if not candidates:
            print(f"No unloaded DLLs found under {sys.base_prefix}; nothing to demonstrate.")
            return 1

        loaded = 0
        for path in candidates:
            if loaded >= args.count:
                break
            try:
                keep_alive.append(ctypes.WinDLL(path))
            except OSError as e:
                print(f"  skipped {os.path.basename(path)}: {e}")
                continue
            loaded += 1
            print(f"  [{loaded}/{args.count}] loaded {path}", flush=True)
            if loaded < args.count:
                time.sleep(args.interval)

        print(f"\nDone loading {loaded} module(s). Staying alive; "
              "watch the dashboard, Ctrl+C to exit.", flush=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
