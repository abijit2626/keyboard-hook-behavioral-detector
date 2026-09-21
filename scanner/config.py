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
ML_RISK_WEIGHT_SCALE = 20
KEYLOGGER_API_WEIGHT_SCALE = 25

# --- System Settings ---
WINDOWS_DIR = os.environ.get("WINDIR", "C:\\Windows").lower()
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
