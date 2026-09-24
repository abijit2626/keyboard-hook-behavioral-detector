"""
Configuration settings for Keylogger Detection System.
"""
import os

# --- Controller Settings ---
# Time between scan cycles in seconds
SCAN_INTERVAL = 10 

# Run analysis after this many scan cycles
ANALYZE_EVERY = 3

# How many of the most recent snapshot files to keep on disk. Older ones
# are pruned after each analysis cycle so the snapshots/ directory and the
# per-cycle temporal_analyzer.py history rebuild don't grow without bound
# on a long-running deployment. Must stay comfortably above ANALYZE_EVERY
# so there are always at least 2 snapshots available to diff.
SNAPSHOT_RETENTION_COUNT = 20

# --- Risk Engine Settings ---
# Points to decay per analysis cycle
# With SCAN_INTERVAL=10 and ANALYZE_EVERY=3, analysis happens every 30 seconds.
# Decay of 5 means a HIGH risk (60) clears in 12 cycles (~6 mins) if behavior stops.
RISK_DECAY = 5

# Risk Thresholds
RISK_MEDIUM_THRESHOLD = 30
RISK_HIGH_THRESHOLD = 60

# Ceiling on risk_score. Without this, a process that keeps generating
# gated events (e.g. a legitimate overlay app reloading its hook DLL every
# time a game launches) can compound its score into the hundreds -- past
# the point where it means anything beyond "still HIGH", and past the
# point where RISK_DECAY (a few points per cycle) can bring it back down
# in a reasonable time once the behavior stops. Comfortably above
# RISK_HIGH_THRESHOLD so HIGH-risk processes stay distinguishable by score,
# not unbounded.
RISK_SCORE_CAP = 150

# Event Risk Weights
# Positive = Adds risk, Negative = Reduces risk
EVENT_WEIGHTS = {
    "SUSPECT_DETECTED": 15,
    "HOOK_APPEARED": 10,
    "NEW_HOOK_MODULE": 35,
    "HOOK_REMOVED": -10
}

# --- ML Risk Model Settings ---
# Maximum extra points an event's ML risk probability (0..1) can add to its
# base weight above, applied as ML_RISK_WEIGHT_SCALE * ml_risk_score.
# ML_RISK_WEIGHT_SCALE scores general "does this PE look like malware"
# (scanner/ml, trained on the real ClaMP dataset). KEYLOGGER_API_WEIGHT_SCALE
# scores the narrower "does this import table look like input-capture
# malware specifically" (scanner/ml/keylogger_signatures.py, mapped to
# MITRE ATT&CK T1056.001 and related techniques). Both are bonuses on top
# of a rule-based trigger; neither can escalate risk on its own.
#
# Deliberately kept smaller than the base EVENT_WEIGHTS (max 35): plenty of
# entirely legitimate software (game overlays, screen-capture/streaming
# tools, RGB lighting apps) legitimately uses hooking, key-state polling,
# raw input, and screen/clipboard capture APIs for hotkeys and recording --
# the same capabilities a keylogger needs, for different reasons. These
# scales control how much that static signal can add on top of a real
# behavioral trigger; they were previously large enough to let one flagged
# event push a process most of the way to HIGH on their own, which defeats
# the point of "bonus, never sole trigger."
ML_RISK_WEIGHT_SCALE = 10
KEYLOGGER_API_WEIGHT_SCALE = 12

# --- System Settings ---
WINDOWS_DIR = os.environ.get("WINDIR", "C:\\Windows").lower()

# Trusted software known to legitimately use keyboard-hook-adjacent
# capabilities (global hotkeys, screen capture, overlays) -- scored 0
# regardless of what the rule engine or either ML/heuristic layer says.
# No static analysis can fully tell "GeForce overlay's Alt+Z hotkey hook"
# apart from "keylogger's hook" from capability alone; this is the
# project's documented answer to that ambiguity (see README: "Trusted
# software must not generate noise"), the same reason Discord and Steam
# are already here. Extend this set for your own machine's overlay/RGB/
# capture software (GeForce Experience/NVIDIA App, AMD Software, Razer
# Synapse, Logitech G HUB, OBS Studio, etc.) -- check the exact process
# name in Task Manager's "Details" tab, since matching is an exact,
# case-insensitive basename comparison.
ALLOWLIST = {
    "discord.exe",
    "signal.exe",
    "chrome.exe",
    "msedge.exe",
    "zoom.exe",
    "teams.exe",
    "slack.exe",
    "steam.exe"
}
