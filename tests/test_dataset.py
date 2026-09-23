"""Sanity checks on the real ClaMP training data (scanner/ml/dataset.py)."""
from scanner.ml.dataset import load_dataset
from scanner.ml.pe_features import FEATURE_NAMES


def test_load_dataset_shape_matches_features():
    X, y = load_dataset()
    assert len(X) == len(y)
    assert all(len(row) == len(FEATURE_NAMES) for row in X)


def test_load_dataset_is_the_real_clamp_set():
    # Regression guard: this is real data (5,210 samples), not a stub/sample.
    X, y = load_dataset()
    assert len(X) > 5000


def test_load_dataset_labels_are_binary():
    _, y = load_dataset()
    assert set(y) <= {0, 1}
    assert 0 in y and 1 in y
