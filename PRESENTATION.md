# Presenting this project on a new Windows machine

## 1. Prerequisites

| Need | Notes |
|---|---|
| Windows 10 / 11, 64-bit | The live scanner is Windows-only (`scanner/scanner.py` exits on other OSes). |
| Python 3.10 – 3.12 | From [python.org](https://www.python.org/downloads/windows/). Keep the **py launcher** option ticked. |
| Git (optional) | Or download the repo as a ZIP and extract it. |
| Internet, for setup only | `pip` needs it once. The demo itself runs fully offline. |

## 2. One-time setup

```powershell
git clone https://github.com/abijit2626/keyboard-hook-behavioral-detector.git
cd keyboard-hook-behavioral-detector
setup_windows.bat -Demo
```

This creates `.venv`, installs the dependencies, **retrains the ML model** on
the bundled ClaMP dataset (a few seconds, and it makes the saved model match
the scikit-learn version just installed), runs the tests (a failure only warns, it does not stop setup), and writes sample
data so the dashboard is populated straight away.

Options (pass to `setup_windows.bat` or `setup_windows.ps1`):
`-SkipTrain` keep the committed model, `-SkipTests`, `-Demo` seed sample data.

If double-clicking is blocked, run the `.bat` from a Command Prompt, or use
`powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Demo`.

## 3. Pre-flight checklist (do this before you go on stage)

- [ ] `setup_windows.bat -Demo` finished with "Setup complete." and tests passed
- [ ] `start_dashboard.bat` opens http://127.0.0.1:5000 and shows 2 HIGH / 1 MEDIUM / 3 LOW
- [ ] `.venv\Scripts\python -m scanner.report` prints the terminal table
- [ ] Browser zoom and terminal font are readable from the back of the room
- [ ] Laptop is on power, sleep is disabled, notifications are off
- [ ] If you plan to show live scanning: `start_monitor.bat` ran for at least a minute with no errors (see §5)
- [ ] You have the repo on a second device / USB stick in case the network or laptop fails

## 4. Suggested flow (~10 minutes)

1. **Problem** (1 min): many legitimate apps install keyboard hooks, so
   "has a hook" is not a verdict. Read the *Design Philosophy* section of the README.
2. **Pipeline** (2 min): capability → behavior → persistence → explainable
   risk. Show the *Layered Risk Signals* table: rule engine, malware ML,
   MITRE ATT&CK API fingerprint.
3. **Dashboard** (3 min): `start_dashboard.bat`. Point out the HIGH rows,
   the ML % and keylogger-API % bars, ATT&CK tags, and that the allowlisted
   `discord.exe` scores 0. Use the risk filter and search box.
4. **Why it isn't a black box** (2 min): `scanner/ml/keylogger_signatures.py`
   (weights + MITRE citations) and `scanner/config.py` (thresholds, allowlist).
   Stress: a model score alone never crosses a threshold; it only amplifies a
   rule-based trigger.
5. **Live scan** (optional, 2 min): see §5.
6. **Tests and CI** (1 min): `.venv\Scripts\python -m pytest -v`, and the CI badge in the README.

The dashboard rows from `-Demo` are **sample data** with made-up executables.
Say so if asked; real results come from the live monitor.

## 5. Live scanning (optional)

```powershell
start_monitor.bat        # window 1: scans every 10s, analyzes every 3rd scan (~30s)
start_dashboard.bat      # window 2
```

- The first risk rows appear after the first analysis cycle (~30 s).
- Run the monitor from an **Administrator** terminal for the best coverage;
  without it, some processes raise `AccessDenied` and are skipped (logged at DEBUG).
- Real data and demo data share `temporal_state.json`. For a clean live run,
  first remove the sample data: `.venv\Scripts\python seed_demo_state.py --clear`
  (it only deletes files it created itself; use `--force` to override).
- To show a detection live without writing any malware, use a harmless
  AutoHotkey v2 script that registers a hotkey (the README's validation setup),
  then watch it appear in the dashboard after a few cycles. Expect it to land
  LOW/MEDIUM: persistence and several corroborating signals are required to reach HIGH.
- Restore the demo view any time with `seed_demo_state.py --force`.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| "running scripts is disabled on this system" | Use `setup_windows.bat`, or `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1` |
| "No Python 3.10-3.12 found" | Install Python 3.11, reopen the terminal, re-run setup. Python 3.13+ is untested by this project. |
| `pip install` fails / times out | Check the network or proxy; setup can be re-run safely. |
| Model load warning or `InconsistentVersionWarning` | Run `.venv\Scripts\python train_model.py` to regenerate the model for this machine. |
| Dashboard shows "no data" | Run `seed_demo_state.py`, or let `start_monitor.bat` finish a cycle. Run both from the project folder (the state file is relative to the working directory). |
| Port 5000 already in use | `start_dashboard.bat --port 8080` and open http://127.0.0.1:8080 |
| Want a fresh start | Delete `temporal_state.json`, `temporal_events.json`, `snapshots\*.json` and `logs\` |
| Windows-only test fails | `tests\test_windows_signing.py` needs `pwsh.exe` (PowerShell 7) installed, as described in `win_authenticode.py`. Install it or skip that file with `pytest --ignore=tests/test_windows_signing.py`. |

## 7. Safety notes for the audience

User-mode and read-only: it never captures keystrokes, injects code or
modifies the system, and no real malware is collected or run. The dashboard
binds to `127.0.0.1` only; don't use `--host 0.0.0.0` on a shared or
conference network.
