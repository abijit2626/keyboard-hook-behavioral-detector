"""
Keylogger-specific capability fingerprinting.

scanner.ml.pe_features / scanner.ml_classifier answer "does this file's PE
structure look like malware in general" (trained on the real ClaMP
dataset). That question is deliberately generic -- there is no public,
labeled dataset of "PE files, tagged keylogger-vs-not" to train a second
classifier on, and this project does not collect or run real malware to
build one (see README: Safety & Ethics).

Instead, this module answers a narrower, keylogger-specific question the
same way real EDR/AV "capability" engines do it: by statically inspecting
the import table for the exact Windows APIs that input-capture malware
needs to call, and weighting them by how specific each one is to that
behavior. It's a deterministic, explainable rule engine, not a black box
-- consistent with this project's own stated design principle
("Decisions must be explainable").

Every category below is mapped to a MITRE ATT&CK (Enterprise) technique
ID, current as of the ATT&CK v16 framework:

  T1056.001  Input Capture: Keylogging        (hooking / polling APIs)
  T1113      Screen Capture                   (screenshot APIs, often paired with keyloggers)
  T1115      Clipboard Data                   (clipboard capture)
  T1056.004  Input Capture: Credential API Hooking
  T1547.001  Boot or Logon Autostart Execution: Registry Run Keys
  T1071.001  Application Layer Protocol: Web Protocols  (exfiltration)
  T1622      Debugger Evasion
  T1497      Virtualization/Sandbox Evasion

Reference: MITRE ATT&CK, https://attack.mitre.org/ (Enterprise Matrix).
"""
import pefile

# Each category: (MITRE ATT&CK technique, weight, API names to match).
# Weight reflects how specific/damning that API is to input-capture
# malware on its own -- a low-level keyboard hook is far more telling
# than, say, a registry write, which plenty of benign installers do too.
_SIGNATURE_CATEGORIES = [
    {
        "name": "low_level_hook",
        "technique": "T1056.001",
        "weight": 0.40,
        "apis": {
            "SetWindowsHookExA", "SetWindowsHookExW",
            "UnhookWindowsHookEx", "CallNextHookEx",
        },
    },
    {
        "name": "keystate_polling",
        "technique": "T1056.001",
        "weight": 0.25,
        "apis": {"GetAsyncKeyState", "GetKeyState", "GetKeyboardState"},
    },
    {
        "name": "raw_input_capture",
        "technique": "T1056.001",
        "weight": 0.20,
        "apis": {"RegisterRawInputDevices", "GetRawInputData"},
    },
    {
        "name": "screen_capture",
        "technique": "T1113",
        "weight": 0.10,
        "apis": {"BitBlt", "CreateCompatibleBitmap", "GetDIBits"},
    },
    {
        "name": "clipboard_capture",
        "technique": "T1115",
        "weight": 0.08,
        "apis": {"GetClipboardData", "OpenClipboard", "SetClipboardViewer"},
    },
    {
        "name": "window_tracking",
        "technique": "T1056.001",
        "weight": 0.05,
        "apis": {"GetForegroundWindow", "GetWindowTextA", "GetWindowTextW"},
    },
    {
        "name": "persistence_registry_run",
        "technique": "T1547.001",
        "weight": 0.05,
        "apis": {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"},
    },
    {
        "name": "network_exfiltration",
        "technique": "T1071.001",
        "weight": 0.10,
        "apis": {
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
            "HttpSendRequestA", "HttpSendRequestW", "send", "WSASend",
        },
    },
    {
        "name": "anti_debug",
        "technique": "T1622",
        "weight": 0.05,
        "apis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"},
    },
    {
        "name": "sandbox_evasion",
        "technique": "T1497",
        "weight": 0.05,
        "apis": {"GetTickCount", "GetTickCount64", "Sleep", "QueryPerformanceCounter"},
    },
]

# Sum of all category weights, used to normalize the final score to [0, 1].
_MAX_SCORE = sum(cat["weight"] for cat in _SIGNATURE_CATEGORIES)


def _imported_api_names(pe):
    """Set of imported function names (ANSI/Unicode variants included)."""
    names = set()
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return names

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                names.add(imp.name.decode("latin-1", errors="ignore"))
    return names


def extract_keylogger_signals(filepath):
    """
    Score a PE file's import table against known input-capture API
    signatures.

    Returns a dict:
        {
            "score": float in [0, 1],
            "matched_categories": [{"name", "technique", "weight", "apis": [...]}]
        }
    or None if the file couldn't be parsed as a PE.
    """
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except Exception:
        return None

    try:
        imported = _imported_api_names(pe)

        matched_categories = []
        raw_score = 0.0
        for category in _SIGNATURE_CATEGORIES:
            hit_apis = sorted(imported & category["apis"])
            if hit_apis:
                raw_score += category["weight"]
                matched_categories.append({
                    "name": category["name"],
                    "technique": category["technique"],
                    "weight": category["weight"],
                    "apis": hit_apis,
                })

        return {
            "score": round(raw_score / _MAX_SCORE, 4) if _MAX_SCORE else 0.0,
            "matched_categories": matched_categories,
        }
    except Exception:
        return None
    finally:
        pe.close()
