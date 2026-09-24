# Keyboard Hook Behavioral Detector (Windows)

[![CI](https://github.com/abijit2626/keyboard-hook-behavioral-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/abijit2626/keyboard-hook-behavioral-detector/actions/workflows/ci.yml)

A **Windows user-mode behavioral monitoring tool** that identifies processes
capable of installing keyboard hooks and evaluates their risk **over time**,
using contextual, temporal, and machine-learning signals layered on top of
each other.

It does **not** intercept keystrokes, inject code, or run at kernel level.
It focuses on **capability detection, behavior observation, and risk
persistence** — the same approach modern EDR (Endpoint Detection & Response)
telemetry agents use.

> This is **not a malware classifier** you point at a single file and get a
> verdict from. It is a **behavioral risk assessment pipeline**: capability →
> behavior → persistence → explainable risk level.

---

## Quick Start

```bash
pip install -r requirements.txt

# One-time (or after editing the training data/features): train the ML models
python train_model.py

# Run the monitor (Windows only — scans, analyzes, scores risk on a loop)
python main_controller.py

# In another terminal, at any time: see the current risk picture
python -m scanner.report        # terminal table
python -m scanner.dashboard     # web dashboard at http://127.0.0.1:5000
```

`scanner/report.py` prints a live-updating table like:

```
RISK  SCORE  MALWARE ML  KEYLOGGER API  ATT&CK                            EXECUTABLE
----  -----  ----------  -------------  --------------------------------  ----------------------------------------
HIGH  125    95%         85%            keystate_polling, low_level_hook  C:\Users\bob\AppData\Local\Temp\evil.exe
LOW   22     40%         15%            screen_capture                    C:\Tools\mid.exe
LOW   11     5%          2%             -                                 C:\Program Files\App\legit.exe

3 process(es) tracked -- 1 HIGH, 0 MEDIUM.
```

`python -m scanner.dashboard` serves the same data as a dark, auto-refreshing
web page — a sidebar with Overview / Processes / About sections, live-updating
stat tiles, a sortable and filterable risk table, and per-process ML/ATT&CK
score bars. See *Web Dashboard* below.

---

## Design Philosophy

Traditional security tools often fail by making immediate judgments based on
single observations. This project follows a different philosophy:

> **Detect capability → observe behavior → correlate real signals → escalate only if patterns persist**

Key principles:
- Capability does not imply malicious intent
- Persistence amplifies risk, it does not create it
- Trusted software must not generate noise
- Every risk signal — rule-based or ML — must be able to explain itself
- A model score alone never crosses a risk threshold; it only amplifies a rule-based trigger

---

## What This Tool Detects

The scanner identifies **keyboard-hook-capable processes** by observing:

- Use of `user32.dll`
- Presence of non-Windows DLLs
- Executables running outside system directories
- Digital signature status
- Execution context (user space vs system space)

Processes are classified as:
- `EXE_HOOK_SUSPECT`
- `DLL_HOOK_SUSPECT`

These are **capability labels**, not verdicts.

---

## Layered Risk Signals

Every suspect gets scored by three independent, complementary layers. Any
one of them firing alone is not enough to escalate risk — see *Design
Philosophy* above.

| Layer | Question it answers | How | File |
|---|---|---|---|
| **Rule engine** | Does this process have hook capability, and is it persisting/escalating over time? | DLL/signature inspection + temporal event weights & decay | `keyboard_hook_detector.py`, `temporal_risk_engine.py` |
| **Malware ML** | Does this executable's PE structure look like malware *in general*? | RandomForest trained on 5,210 real labeled executables | `scanner/ml/` |
| **Keylogger API fingerprint** | Does this executable's import table specifically look like input-capture malware? | Weighted static signature match against MITRE ATT&CK-mapped Windows APIs | `scanner/ml/keylogger_signatures.py` |

Both ML/heuristic layers only ever add a bonus on top of an already-positive
rule-based event weight (`ML_RISK_WEIGHT_SCALE`, `KEYLOGGER_API_WEIGHT_SCALE`
in `config.py`) — a process allowlisted or with no rule-based trigger scores
0 regardless of what either model says.

### False Positives (Expected and Handled)

Many legitimate applications use keyboard hooks, including Discord, Signal,
browsers, accessibility tools, and automation utilities. This is expected
behavior. False positives are reduced using:
- Risk scoring (LOW / MEDIUM / HIGH)
- Allowlisting of trusted software
- Temporal persistence gating
- Risk decay over time
- Two independent ML/heuristic risk probabilities that augment — never
  replace — the rule-based score

A process must demonstrate **both suspicion and persistence** to escalate.

---

## Machine Learning: General Malware Detection

`scanner/ml/` trains a **RandomForestClassifier** (scikit-learn) on a real,
public dataset of Windows PE (executable) header features, to estimate the
probability that a hook-capable process's executable looks like malware.

**Dataset: [ClaMP](https://github.com/urwithajit9/ClaMP)** (Classification
of Malware with PE headers) by Ajit Kumar — 5,210 real Windows executables
(2,722 malware + 2,488 benign), each reduced to header-level features via
`pefile`. Committed at `scanner/ml/data/clamp_integrated.csv`. Its scripts
state *"No license required for any kind of reuse"* — credited here
accordingly.

**Features (67):** `scanner/ml/pe_features.py` re-implements ClaMP's own
feature extraction (`integrated_features_extraction.py`) for modern
Python 3, so the same code — not a lookalike — runs at both training and
scan time:
- Raw `IMAGE_DOS_HEADER` / `FILE_HEADER` fields (`e_cblp`, `e_lfanew`, section count, ...)
- All 15 `FILE_HEADER.Characteristics` flag bits (DLL, executable image, stripped symbols, ...)
- `OPTIONAL_HEADER` fields, with a few (`ImageBase`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `LoaderFlags`) turned into the same well-formedness boolean checks ClaMP uses
- All 11 `DllCharacteristics` flag bits (ASLR, NX, CFG, ...)
- Per-section Shannon entropy of `.text` / `.data`, overall file entropy and size, count of non-standard ("suspicious") section names, and whether version-info resources are present

Two of ClaMP's original 69 columns, `packer` and `packer_type`, are dropped:
they depend on a PEiD signature database compiled as YARA rules that this
project doesn't bundle. Everything else is computed directly from the file,
matching ClaMP's own definitions.

**Training:**
```
python train_model.py
```
Trains on an 80/20 stratified split of the real dataset and prints
accuracy, a classification report, a confusion matrix, and feature
importances — on the current dataset this lands around **99% accuracy** on
held-out real samples. Saves to `scanner/ml/artifacts/clamp_pe_model.joblib`.
A pre-trained model is already committed, so the tool works out of the box.

---

## Machine Learning: Keylogger-Specific Fingerprinting (MITRE ATT&CK)

The malware-ML layer above answers "does this look like malware in
general" — it isn't keylogger-specific, and there's no public, labeled
dataset of "PE files tagged keylogger-vs-not" to train a classifier on
(this project also never collects or runs real malware to build one — see
*Safety & Ethics*). So `scanner/ml/keylogger_signatures.py` answers the
narrower question the way real EDR/AV "capability" engines actually do it:
by statically inspecting the **import table** for the exact Windows APIs
input-capture malware needs to call, weighted by how specific each one is,
and normalized to a 0–1 score.

This is a deterministic, explainable rule engine — not a black box —
consistent with this project's own design principle that every decision
must be explainable. Every category is mapped to a current MITRE ATT&CK
(Enterprise, v16) technique:

| Category | Technique | Example APIs |
|---|---|---|
| Low-level keyboard hooks | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) Input Capture: Keylogging | `SetWindowsHookExA/W`, `CallNextHookEx` |
| Key-state polling | T1056.001 | `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState` |
| Raw input capture | T1056.001 | `RegisterRawInputDevices`, `GetRawInputData` |
| Screen capture | [T1113](https://attack.mitre.org/techniques/T1113/) Screen Capture | `BitBlt`, `CreateCompatibleBitmap` |
| Clipboard capture | [T1115](https://attack.mitre.org/techniques/T1115/) Clipboard Data | `GetClipboardData`, `OpenClipboard` |
| Foreground-window tracking | T1056.001 | `GetForegroundWindow`, `GetWindowTextW` |
| Registry Run-key persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot/Logon Autostart | `RegSetValueExW`, `RegCreateKeyExW` |
| Network exfiltration | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols | `InternetOpenW`, `HttpSendRequestW` |
| Debugger evasion | [T1622](https://attack.mitre.org/techniques/T1622/) Debugger Evasion | `IsDebuggerPresent` |
| Sandbox evasion | [T1497](https://attack.mitre.org/techniques/T1497/) Virtualization/Sandbox Evasion | `GetTickCount`, `QueryPerformanceCounter` |

A process needs `SetWindowsHookExA` *and* `GetAsyncKeyState` *and*
`GetForegroundWindow` imported to score ~0.53; a benign binary that merely
calls `GetTickCount` for timing scores ~0.05. The full weighting and API
list lives in `scanner/ml/keylogger_signatures.py`, with MITRE citations in
its docstring.

---

## Inference: How a Score Reaches a Risk Level

Every suspect entry `keyboard_hook_detector.py` produces gets scored by
both ML/heuristic layers on the actual executable on disk (`ml_risk_score`,
`keylogger_api_score`). Those scores flow through `temporal_analyzer.py`'s
events into `temporal_risk_engine.py`, where each adds an explainable bonus
on top of the rule-based event weight — `ML_RISK_WEIGHT_SCALE * ml_risk_score`
and `KEYLOGGER_API_WEIGHT_SCALE * keylogger_api_score` — but **only** for
events that already carry a positive rule-based weight. A process still
needs a rule-based trigger (`SUSPECT_DETECTED`, `NEW_HOOK_MODULE`, ...)
before either model can move its risk level, and allowlisted processes
score 0 regardless of what either model says.

---

## Web Dashboard

```
python -m scanner.dashboard              # http://127.0.0.1:5000, local-only by default
python -m scanner.dashboard --port 8080  # custom port
python -m scanner.dashboard --host 0.0.0.0   # opt-in to expose beyond localhost
```

A small read-only Flask app (`scanner/dashboard/`) that reads the exact same
`temporal_state.json` as `scanner/report.py` — it never touches the
scanner/analyzer/risk-engine pipeline, so it's safe to leave running
alongside `main_controller.py` on Windows, or point at a copy of the state
file from any OS to review results afterward.

- **Sidebar shell** — Overview / Processes / About, with scroll-spy nav highlighting; collapses to a hamburger-triggered overlay below 760px
- **Stat tiles** — total tracked, HIGH / MEDIUM / LOW counts, each with its own status-colored accent
- **Process table** — risk badge, score (click-to-sort), malware-ML % bar, keylogger-API % bar, matched ATT&CK technique tags, executable path, last-seen (relative time); a colored left-edge bar marks each row's risk level
- **Live** — polls `/api/state` every 3s and re-renders in place, no page reload; a manual refresh button and a live/stale status pill in the top bar
- **Search + segmented risk filter** (All / High / Medium / Low), with a proper empty state for "no data yet" vs. "nothing matches this filter"
- Binds to `127.0.0.1` by default — deliberately local-only. This tool's own
  telemetry (which processes look suspicious, on which machine) is itself
  sensitive; it doesn't go on the network without an explicit `--host` flag.

No new detection logic lives here — same rule that governs the rest of the
project: the dashboard only ever displays what `temporal_risk_engine.py`
already decided, it never re-scores anything client-side.

---

## Architecture
```
project-root/
├── scanner/
│ ├── scanner.py                  # Single scan cycle (snapshot)
│ ├── keyboard_hook_detector.py   # Capability detection + signature checks
│ ├── win_authenticode.py         # Authenticode signature check (WinVerifyTrust, no subprocess)
│ ├── ml/
│ │ ├── analysis.py               # Shared entry point: one PE parse, both ML/heuristic layers, cached
│ │ ├── pe_features.py            # Static PE-header feature extraction
│ │ ├── keylogger_signatures.py   # MITRE ATT&CK API fingerprinting
│ │ ├── dataset.py                # Loads the real ClaMP CSV
│ │ ├── data/                     # ClaMP_Integrated-5210 dataset (CSV)
│ │ ├── model.py                  # Model load + inference
│ │ └── artifacts/                # Trained model (.joblib)
│ ├── temporal_analyzer.py        # Behavior change detection
│ ├── temporal_risk_engine.py     # Risk persistence + decay
│ ├── report.py                   # Terminal risk table
│ ├── dashboard/                  # Web dashboard (Flask, read-only)
│ │ ├── app.py                    # Routes: / and /api/state
│ │ ├── templates/index.html
│ │ └── static/ (style.css, app.js)
│ ├── config.py
│ └── __init__.py
│
├── snapshots/                    # Timestamped scan results (auto-pruned)
├── temporal_state.json           # Persistent risk memory
├── train_model.py                # ML training script
├── main_controller.py            # Scheduler / orchestrator
├── tests/                        # pytest suite (Windows-only tests auto-skip elsewhere)
├── .github/workflows/ci.yml      # Import check, ML training gate, tests (Ubuntu + Windows)
└── README.md
```

---

## How It Works (High Level)

1. **Scanner**
   - Enumerates processes
   - Detects keyboard-hook capability
   - Scores each suspect with both ML/heuristic layers (`ml_risk_score`, `keylogger_api_score`)
   - Writes a timestamped snapshot

2. **Temporal Analyzer**
   - Compares snapshots
   - Emits behavior-change events (carrying both scores)

3. **Temporal Risk Engine**
   - Maintains long-term risk state
   - Applies gated persistence scoring + ML/heuristic bonuses
   - Decays risk when behavior stabilizes

4. **Report / Dashboard**
   - `python -m scanner.report` prints the current risk table on demand
   - `python -m scanner.dashboard` serves the same data as a live web page

Older snapshots are pruned automatically after each analysis cycle
(`SNAPSHOT_RETENTION_COUNT` in `config.py`) so a long-running deployment
doesn't accumulate an unbounded history on disk.

---

## Performance

An earlier version of this pipeline was slow enough per cycle to notice.
The cause wasn't Python itself — it was a handful of specific, fixable
costs being paid repeatedly:

| Cost | Fix |
|---|---|
| Signature checks shelled out to `powershell.exe` per file (100ms–1s+ startup each, plus a possible network revocation check) | `win_authenticode.py` calls `WinVerifyTrust` directly via `ctypes` — no subprocess, no network round trip (`WTD_REVOKE_NONE`) |
| `main_controller.py` spawned a fresh `python -m scanner.scanner` subprocess every `SCAN_INTERVAL` — cold-importing scikit-learn/pefile and reloading the trained model from disk (~1s) on every cycle | `main_controller.py` now calls `scanner.scanner.main()` / `scanner.temporal_analyzer.analyze()` in-process, so the model and imports stay warm for the life of the process |
| The malware-ML and keylogger-fingerprint layers each independently opened and parsed the same PE file | `scanner/ml/analysis.py` opens and parses it once, shares the same `pefile.PE` object with both |
| A process still running on the next cycle got fully re-analyzed (PE parse, entropy, import scan) from scratch | `analyze_executable()` is cached per executable path (`functools.lru_cache`) |

Net effect, measured in this repo: once the model is warm, scoring one
executable (PE parse + both ML/heuristic layers) takes **~75ms**; a
repeat of the same path is **sub-millisecond** (cache hit). The ~1s
model-load cost now happens once at startup instead of every cycle.

---

## Development / Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

`tests/` covers the OS-independent logic directly — real dataset loading,
the risk-engine's gating/decay/allowlist/ML-bonus math, the keylogger
signature weighting, and the report table — without needing Windows.
`tests/test_windows_signing.py` is Windows-only (auto-skipped elsewhere)
and is the one place that exercises real binaries rather than mocks: the
`WinVerifyTrust` signature check against an embedded-signed third-party
executable (`pwsh.exe` — see `win_authenticode.py`'s docstring for why
a core Windows binary like `notepad.exe` wouldn't be representative
there), and live PE scoring / full detector-cycle tests against
`notepad.exe`.

CI (`.github/workflows/ci.yml`) runs on every push/PR to `main`: an
import/syntax check, a retrain-and-validate pass against the real ClaMP
dataset (fails if accuracy drops below 90%), the cross-platform test
suite on Ubuntu, and the Windows-only suite on a `windows-latest` runner.

---

## What Makes This Unique

Most student keylogger-detector projects stop at one of: signature/hash
matching, or a single black-box classifier. This project layers three
independent signal types the way a real detection engineering team would:

1. A **rule-based capability + temporal-persistence engine** (explainable, gated, decaying)
2. A **general malware classifier** trained on **real, labeled data** (not synthetic)
3. A **MITRE ATT&CK-mapped keylogger-specific API fingerprint** — the same static-capability-fingerprinting approach real EDR/AV products use, cited against the current ATT&CK framework rather than an ad-hoc keyword list

No single signal can escalate a process to HIGH risk on its own — every
path to escalation requires a real rule-based trigger, amplified (never
created) by explainable ML/heuristic evidence.

---

## Safety & Ethics

- User-mode only
- Read-only inspection
- No API hooking
- No keystroke capture
- No code injection
- No system modification
- No real malware samples are collected, run, or required — the ML layer trains on a pre-extracted, already-public feature dataset, and the keylogger fingerprint layer is a documented static rule engine, not something trained on malicious samples

This tool is suitable for **learning, research, and behavioral analysis**.

---

## Tested Environment

- Windows 10 / 11 (64-bit)
- Python 3.10 / 3.11
- AutoHotkey v2 (for validation)

---

## Intended Use

This project is intended for:
- Security research
- Learning Windows internals
- Behavioral detection experimentation
- Portfolio / interview demonstration

It is **not** intended as a drop-in security product.

---

## Disclaimer

This software is provided for educational and research purposes only.
