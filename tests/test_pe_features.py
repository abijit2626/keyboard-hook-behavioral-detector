"""
scanner/ml/pe_features.py tests that don't need a real Windows PE file
(real-file extraction is covered on Windows CI by test_windows_signing.py).
"""
from scanner.ml.pe_features import FEATURE_NAMES, extract_pe_features


def test_feature_names_count_matches_documented_67():
    assert len(FEATURE_NAMES) == 67


def test_feature_names_has_no_duplicates():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_extract_pe_features_returns_none_for_missing_file():
    assert extract_pe_features("/nonexistent/not-a-real-file.exe") is None


def test_extract_pe_features_returns_none_for_non_pe_file(tmp_path):
    not_a_pe = tmp_path / "not_a_pe.exe"
    not_a_pe.write_bytes(b"this is definitely not a PE file")
    assert extract_pe_features(str(not_a_pe)) is None
