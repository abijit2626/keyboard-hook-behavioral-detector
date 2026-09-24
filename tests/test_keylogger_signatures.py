"""
scanner/ml/keylogger_signatures.py scoring-logic tests, using a fake `pe`
object that only implements DIRECTORY_ENTRY_IMPORT -- exercises the real
weighting/normalization/MITRE-mapping logic without needing a real PE file
(real-file scoring is covered on Windows CI by test_windows_signing.py).
"""
from scanner.ml.keylogger_signatures import (
    _MAX_SCORE,
    _SIGNATURE_CATEGORIES,
    extract_keylogger_signals,
    score_from_pe,
)


class _FakeImport:
    def __init__(self, name):
        self.name = name.encode()


class _FakeImportEntry:
    def __init__(self, names):
        self.imports = [_FakeImport(n) for n in names]


class _FakePE:
    def __init__(self, api_names):
        self.DIRECTORY_ENTRY_IMPORT = [_FakeImportEntry(api_names)]


def test_max_score_is_sum_of_category_weights():
    assert _MAX_SCORE == sum(cat["weight"] for cat in _SIGNATURE_CATEGORIES)
    assert _MAX_SCORE > 0


def test_benign_imports_score_zero():
    result = score_from_pe(_FakePE(["MessageBoxA", "CreateWindowExW", "malloc"]))
    assert result["score"] == 0.0
    assert result["matched_categories"] == []


def test_classic_keylogger_fingerprint_scores_high():
    result = score_from_pe(_FakePE([
        "SetWindowsHookExA", "CallNextHookEx", "GetAsyncKeyState", "GetForegroundWindow",
    ]))
    names = {cat["name"] for cat in result["matched_categories"]}
    assert names == {"low_level_hook", "keystate_polling", "window_tracking"}
    # Should dominate a benign score by a wide margin.
    assert result["score"] > 0.5


def test_score_is_normalized_to_unit_interval():
    all_apis = [api for cat in _SIGNATURE_CATEGORIES for api in cat["apis"]]
    result = score_from_pe(_FakePE(all_apis))
    assert result["score"] == 1.0


def test_extract_keylogger_signals_returns_none_for_missing_file():
    assert extract_keylogger_signals("/nonexistent/not-a-real-file.exe") is None
