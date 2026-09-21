"""
Feature extraction for the ML risk model.

Turns a suspect entry (as produced by scanner.keyboard_hook_detector) into a
fixed-length numeric feature vector. Kept separate from the detector so the
same code path is used both at training time (scanner/ml/dataset.py) and at
inference time (scanner/ml_classifier.py).
"""

FEATURE_NAMES = [
    "is_dll_hook",
    "num_suspicious_dlls",
    "unsigned_dll_ratio",
    "exe_signed",
    "outside_program_files",
    "path_depth",
    "in_temp_or_appdata",
]


def extract_features(entry):
    """Build the feature vector (list[float], order matches FEATURE_NAMES)."""
    is_dll_hook = 1 if entry.get("type") == "DLL_HOOK_SUSPECT" else 0

    modules = entry.get("suspicious_modules") or []
    num_suspicious_dlls = len(modules)
    if modules:
        unsigned = sum(1 for m in modules if not m.get("signed"))
        unsigned_dll_ratio = unsigned / len(modules)
    else:
        unsigned_dll_ratio = 0.0

    exe_signed = 1 if entry.get("signed") else 0

    exe_path = (entry.get("executable") or "").lower()
    outside_program_files = 0 if "program files" in exe_path else 1
    path_depth = exe_path.count("\\") + exe_path.count("/")
    in_temp_or_appdata = 1 if any(
        marker in exe_path
        for marker in ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/")
    ) else 0

    return [
        float(is_dll_hook),
        float(num_suspicious_dlls),
        float(unsigned_dll_ratio),
        float(exe_signed),
        float(outside_program_files),
        float(path_depth),
        float(in_temp_or_appdata),
    ]
