# Keyboard Hook Behavioral Detector (Windows)

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
python -m scanner.report
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

## Architecture
```
project-root/
├── scanner/
│ ├── scanner.py                  # Single scan cycle (snapshot)
│ ├── keyboard_hook_detector.py   # Capability detection + ML/heuristic scoring
│ ├── ml_classifier.py            # Malware-ML integration point
│ ├── ml/
│ │ ├── pe_features.py            # Static PE-header feature extraction
│ │ ├── keylogger_signatures.py   # MITRE ATT&CK API fingerprinting
│ │ ├── dataset.py                # Loads the real ClaMP CSV
│ │ ├── data/                     # ClaMP_Integrated-5210 dataset (CSV)
│ │ ├── model.py                  # Model load + inference
│ │ └── artifacts/                # Trained model (.joblib)
│ ├── temporal_analyzer.py        # Behavior change detection
│ ├── temporal_risk_engine.py     # Risk persistence + decay
│ ├── report.py                   # Human-readable risk table
│ ├── config.py
│ └── __init__.py
│
├── snapshots/                    # Timestamped scan results (auto-pruned)
├── temporal_state.json           # Persistent risk memory
├── train_model.py                # ML training script
├── main_controller.py            # Scheduler / orchestrator
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

4. **Report**
   - `python -m scanner.report` prints the current risk table on demand

Older snapshots are pruned automatically after each analysis cycle
(`SNAPSHOT_RETENTION_COUNT` in `config.py`) so a long-running deployment
doesn't accumulate an unbounded history on disk.

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
