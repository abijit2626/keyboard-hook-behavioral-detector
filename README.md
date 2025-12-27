# Keyboard Hook Behavioral Detector (Windows)

## Overview

This project is a **Windows user-mode behavioral monitoring tool** designed to identify **processes capable of installing keyboard hooks** and to **evaluate their risk over time** using contextual and temporal analysis.

It does **not** attempt to intercept keystrokes, inject code, or operate at kernel level.  
Instead, it focuses on **capability detection, behavior observation, and risk persistence** — similar in spirit to modern EDR telemetry agents.

⚠️ This is **not a malware classifier**.  
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

A process must demonstrate **both suspicion and persistence** to escalate.

---

## Architecture
```
project-root/
├── scanner/
│ ├── scanner.py # Single scan cycle (snapshot)
│ ├── keyboard_hook_detector.py # Capability detection + base risk
│ ├── temporal_analyzer.py # Behavior change detection
│ ├── temporal_risk_engine.py # Risk persistence + decay
│ ├── config.py
│ └── init.py
│
├── snapshots/ # Timestamped scan results
├── temporal_state.json # Persistent risk memory
├── main_controller.py # Scheduler / orchestrator
└── README.md
```


---

## How It Works (High Level)

1. **Scanner**
   - Enumerates processes
   - Detects keyboard-hook capability
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
