"""
Configuration settings for Keylogger Detection System.
"""
import os

# --- Controller Settings ---
# Time between scan cycles in seconds
SCAN_INTERVAL = 10 

# Run analysis after this many scan cycles
ANALYZE_EVERY = 3

# --- Risk Engine Settings ---
# Points to decay per analysis cycle
# With SCAN_INTERVAL=120 and ANALYZE_EVERY=3, analysis happens every 6 minutes.
# Decay of 5 means a HIGH risk (60) clears in 12 cycles (~72 mins) if behavior stops.
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
ML_RISK_WEIGHT_SCALE = 20

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
