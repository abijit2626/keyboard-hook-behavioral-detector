"""
Synthetic training data for the ML risk model.

There is no public, labeled dataset of "processes that install keyboard
hooks, labeled benign vs. suspicious" -- and collecting one would mean
running real malware, which this project deliberately never does (see
README: user-mode, read-only, no keystroke capture). Instead, this module
generates synthetic feature vectors from a documented behavioral model of
what tends to distinguish legitimate hook users (Discord, accessibility
tools, IME helpers, ...) from a keylogger-style process, using the exact
same feature space the live detector extracts in scanner/ml/features.py.

This is a deliberate, disclosed simplification for an educational project.
It is not a claim of real-world detection accuracy -- see README's
"Machine Learning Component" section.
"""
import random

from scanner.ml.features import FEATURE_NAMES

assert FEATURE_NAMES == [
    "is_dll_hook",
    "num_suspicious_dlls",
    "unsigned_dll_ratio",
    "exe_signed",
    "outside_program_files",
    "path_depth",
    "in_temp_or_appdata",
]


def _sample_benign(rng):
    """A well-behaved hook-capable app: signed, installed, shallow path."""
    is_dll_hook = rng.random() < 0.3
    num_suspicious_dlls = rng.choice([0, 0, 0, 1]) if is_dll_hook else 0
    unsigned_dll_ratio = rng.uniform(0.0, 0.1) if num_suspicious_dlls else 0.0
    exe_signed = 1 if rng.random() < 0.9 else 0
    outside_program_files = 1 if rng.random() < 0.15 else 0
    path_depth = rng.randint(3, 6)
    in_temp_or_appdata = 1 if rng.random() < 0.05 else 0
    return [
        float(is_dll_hook),
        float(num_suspicious_dlls),
        float(unsigned_dll_ratio),
        float(exe_signed),
        float(outside_program_files),
        float(path_depth),
        float(in_temp_or_appdata),
    ]


def _sample_suspicious(rng):
    """A keylogger-style process: unsigned, DLL-injected, buried in temp/appdata."""
    is_dll_hook = rng.random() < 0.75
    num_suspicious_dlls = rng.randint(1, 4) if is_dll_hook else 0
    unsigned_dll_ratio = rng.uniform(0.5, 1.0) if num_suspicious_dlls else rng.uniform(0.0, 0.3)
    exe_signed = 1 if rng.random() < 0.15 else 0
    outside_program_files = 1 if rng.random() < 0.85 else 0
    path_depth = rng.randint(5, 10)
    in_temp_or_appdata = 1 if rng.random() < 0.6 else 0
    return [
        float(is_dll_hook),
        float(num_suspicious_dlls),
        float(unsigned_dll_ratio),
        float(exe_signed),
        float(outside_program_files),
        float(path_depth),
        float(in_temp_or_appdata),
    ]


def generate_synthetic_dataset(n_samples=2000, seed=42):
    """Return (X, y): balanced synthetic feature vectors and 0/1 labels."""
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n_samples):
        if rng.random() < 0.5:
            X.append(_sample_benign(rng))
            y.append(0)
        else:
            X.append(_sample_suspicious(rng))
            y.append(1)
    return X, y
