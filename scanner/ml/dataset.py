"""
Real training data for the ML risk model: ClaMP (Classification of
Malware with PE headers), a public dataset of PE header features
extracted from 5,210 real Windows executables (2,722 malware + 2,488
benign), built by Ajit Kumar using the `pefile` library.

Source: https://github.com/urwithajit9/ClaMP
        scanner/ml/data/clamp_integrated.csv (ClaMP_Integrated-5210, as
        published in that repo's dataset/ directory)
License: the extraction scripts state "No license required for any kind
        of reuse. If using this script for your work, please refer this
        on your willingness." -- credited here accordingly.

Two of the original 69 columns ('packer', 'packer_type') are dropped:
they require a PEiD signature database compiled as YARA rules that this
project does not bundle, and the live feature extractor in
scanner/ml/pe_features.py does not compute them. Every other column is
real, and this loader casts each of scanner.ml.pe_features.FEATURE_NAMES
straight out of the CSV, so the model trains on the identical feature
space it will see at inference time.
"""
import csv
import os

from scanner.ml.pe_features import FEATURE_NAMES

DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "clamp_integrated.csv")

LABEL_COLUMN = "class"  # 0 = benign, 1 = malware (per ClaMP's own scan_file())


def load_dataset(csv_path=DATASET_PATH):
    """Return (X, y): real feature vectors (FEATURE_NAMES order) and labels."""
    X, y = [], []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            X.append([float(row[name]) for name in FEATURE_NAMES])
            y.append(int(row[LABEL_COLUMN]))
    return X, y
