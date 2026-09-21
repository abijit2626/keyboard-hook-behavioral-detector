# Keyboard Hook Behavioral Detector (Windows)

## Overview

This project is a **Windows user-mode behavioral monitoring tool** designed to identify **processes capable of installing keyboard hooks** and to **evaluate their risk over time** using contextual and temporal analysis.

It does **not** attempt to intercept keystrokes, inject code, or operate at kernel level.  
Instead, it focuses on **capability detection, behavior observation, and risk persistence** — similar in spirit to modern EDR telemetry agents.

 This is **not a malware classifier**.  
It is a **behavioral risk assessment tool**.

---

## Design Philosophy

Traditional security tools often fail by making immediate judgments based on single observations.

This project follows a different philosophy:

> **Detect capability → observe behavior → escalate only if patterns persist**

Key principles:
- Capability does not imply malicious intent
- Persistence amplifies risk, it does not create it
- Trusted software must not generate noise
- Decisions must be explainable

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

## False Positives (Expected and Handled)

Many legitimate applications use keyboard hooks, including:

- Discord
- Signal
- Browsers
- Accessibility tools
- Automation utilities

This is expected behavior.

False positives are reduced using:
- Risk scoring (LOW / MEDIUM / HIGH)
- Allowlisting of trusted software
- Temporal persistence gating
- Risk decay over time
- An ML-based risk probability that augments (never replaces) the rule-based score

A process must demonstrate **both suspicion and persistence** to escalate.

---

## Machine Learning Component

Alongside the hand-tuned rule weights in `config.py`, the detector uses a
**RandomForestClassifier** (scikit-learn) to estimate a probability that a
hook-capable process is behaving like a keylogger, based on the same
observable signals the rule engine already collects:

| Feature | What it captures |
|---|---|
| `is_dll_hook` | DLL-based hook vs. plain EXE capability |
| `num_suspicious_dlls` | Count of non-Windows DLLs loaded |
| `unsigned_dll_ratio` | Fraction of those DLLs lacking a valid signature |
| `exe_signed` | Whether the executable itself is signed |
| `outside_program_files` | Running outside a normal install location |
| `path_depth` | How deeply nested the executable's path is |
| `in_temp_or_appdata` | Running from a Temp/AppData-style path |

Feature extraction lives in `scanner/ml/features.py` and is shared by both
training and inference, so the model always sees exactly what the live
detector sees.

**Training data is synthetic.** There is no public, labeled dataset of real
keyboard-hook malware, and this project deliberately never runs or collects
real malicious samples (see *Safety & Ethics* below). `scanner/ml/dataset.py`
generates feature vectors from a documented behavioral model of "benign
hook user" vs. "keylogger-style process" (signed & installed vs. unsigned &
buried in Temp/AppData, etc.) so the classifier has something real to learn
from. This is an explicit, disclosed simplification for an educational
project — not a claim of real-world detection accuracy.

**Training:**
```
python train_model.py
```
This trains the model on the synthetic dataset, prints accuracy / a
classification report / feature importances, and saves the model to
`scanner/ml/artifacts/hook_risk_model.joblib`. A pre-trained model is
already committed, so the tool works out of the box — re-run the script
any time to retrain.

**Inference:** every suspect entry produced by `keyboard_hook_detector.py`
is scored via `scanner/ml_classifier.py`, attaching an `ml_risk_score`
(0.0–1.0). That score flows through `temporal_analyzer.py`'s events into
`temporal_risk_engine.py`, where it adds an explainable bonus
(`ML_RISK_WEIGHT_SCALE * ml_risk_score`, see `config.py`) on top of the
rule-based event weight — it never fires on its own; a process still needs
a rule-based trigger (e.g. `SUSPECT_DETECTED`, `NEW_HOOK_MODULE`) before the
ML score can move its risk level.

---

## Architecture
```
project-root/
├── scanner/
│ ├── scanner.py # Single scan cycle (snapshot)
│ ├── keyboard_hook_detector.py # Capability detection + base risk
│ ├── ml_classifier.py # ML scoring integration point
│ ├── ml/
│ │ ├── features.py # Shared feature extraction
│ │ ├── dataset.py # Synthetic training data
│ │ ├── model.py # Model load + inference
│ │ └── artifacts/ # Trained model (.joblib)
│ ├── temporal_analyzer.py # Behavior change detection
│ ├── temporal_risk_engine.py # Risk persistence + decay
│ ├── config.py
│ └── init.py
│
├── snapshots/ # Timestamped scan results
├── temporal_state.json # Persistent risk memory
├── train_model.py # ML training script
├── main_controller.py # Scheduler / orchestrator
└── README.md
```


---

## How It Works (High Level)

1. **Scanner**
   - Enumerates processes
   - Detects keyboard-hook capability
   - Scores each suspect with the ML model (`ml_risk_score`)
   - Assigns base risk
   - Writes snapshot

2. **Temporal Analyzer**
   - Compares snapshots
   - Emits behavior change events

3. **Temporal Risk Engine**
   - Maintains long-term risk state
   - Applies gated persistence scoring
   - Decays risk when behavior stabilizes

---

## Safety & Ethics

- User-mode only
- Read-only inspection
- No API hooking
- No keystroke capture
- No code injection
- No system modification

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
