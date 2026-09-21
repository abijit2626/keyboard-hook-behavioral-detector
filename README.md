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
**RandomForestClassifier** (scikit-learn) trained on a real, public dataset
of Windows PE (executable) header features to estimate an independent
probability that a hook-capable process's executable looks like malware.

**Dataset: [ClaMP](https://github.com/urwithajit9/ClaMP)** (Classification
of Malware with PE headers) by Ajit Kumar — 5,210 real Windows executables
(2,722 malware + 2,488 benign), each reduced to header-level features via
`pefile`. It's committed at `scanner/ml/data/clamp_integrated.csv`. Its
scripts state *"No license required for any kind of reuse"*, credited here
accordingly.

**Features (67):** `scanner/ml/pe_features.py` re-implements ClaMP's own
feature extraction (`integrated_features_extraction.py`) for modern
Python 3, so the same code — not a lookalike — runs at both training and
scan time. It reads, per executable:
- Raw `IMAGE_DOS_HEADER` / `FILE_HEADER` fields (`e_cblp`, `e_lfanew`, section count, ...)
- All 15 `FILE_HEADER.Characteristics` flag bits (DLL, executable image, stripped symbols, ...)
- `OPTIONAL_HEADER` fields, with a few (`ImageBase`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `LoaderFlags`) turned into the same well-formedness boolean checks ClaMP uses
- All 11 `DllCharacteristics` flag bits (ASLR, NX, CFG, ...)
- Per-section Shannon entropy of `.text` / `.data`, overall file entropy and size, count of non-standard ("suspicious") section names, and whether version-info resources are present

Two of ClaMP's original 69 columns, `packer` and `packer_type`, are
dropped: they depend on a PEiD signature database compiled as YARA rules
that this project doesn't bundle. Everything else is computed directly
from the file, matching ClaMP's own definitions exactly (see the
docstring/citation in `pe_features.py` and `dataset.py` for details).

**Training:**
```
python train_model.py
```
Trains on an 80/20 stratified split of the real dataset and prints
accuracy, a classification report, a confusion matrix, and feature
importances — on the current dataset this lands around **99% accuracy**
on held-out real samples. Saves the model to
`scanner/ml/artifacts/clamp_pe_model.joblib`. A pre-trained model is
already committed, so the tool works out of the box — re-run any time to
retrain.

**Inference:** every suspect entry produced by `keyboard_hook_detector.py`
has its executable scored via `scanner/ml_classifier.py` (which calls
`pe_features.extract_pe_features()` directly on the running process's exe
on disk), attaching an `ml_risk_score` (0.0–1.0). That score flows through
`temporal_analyzer.py`'s events into `temporal_risk_engine.py`, where it
adds an explainable bonus (`ML_RISK_WEIGHT_SCALE * ml_risk_score`, see
`config.py`) on top of the rule-based event weight — it never fires on its
own; a process still needs a rule-based trigger (e.g. `SUSPECT_DETECTED`,
`NEW_HOOK_MODULE`) before the ML score can move its risk level.

This is genuine static malware analysis (real training data, real PE
parsing), layered as one more signal in the same "capability → behavior →
persistence" pipeline — it does not by itself decide that a process is a
keylogger, and it never inspects keystrokes.

---

## Architecture
```
project-root/
├── scanner/
│ ├── scanner.py # Single scan cycle (snapshot)
│ ├── keyboard_hook_detector.py # Capability detection + base risk
│ ├── ml_classifier.py # ML scoring integration point
│ ├── ml/
│ │ ├── pe_features.py # Static PE-header feature extraction
│ │ ├── dataset.py # Loads the real ClaMP CSV
│ │ ├── data/ # ClaMP_Integrated-5210 dataset (CSV)
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
