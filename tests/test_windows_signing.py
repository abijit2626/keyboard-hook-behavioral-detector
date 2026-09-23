"""
Windows-only smoke tests against real system binaries.

Everything in scanner/win_authenticode.py and scanner/ml/ is written to
degrade gracefully (returns False/None) when it can't do real work, which
is exactly what makes it *look* fine on a non-Windows dev/CI box without
actually proving the WinVerifyTrust ctypes plumbing or the live PE
scoring pipeline works. This file is the check that actually proves it,
using binaries every windows-latest GitHub Actions runner ships with.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows-only: WinVerifyTrust / real PE files"
)

NOTEPAD = r"C:\Windows\System32\notepad.exe"

# A real, embedded-Authenticode-signed executable outside WINDOWS_DIR --
# what is_signed() actually gets called on in this codebase (see
# scanner/win_authenticode.py's module docstring: core Windows binaries
# like notepad.exe are catalog-signed, not embedded-signed, and
# keyboard_hook_detector.py never calls is_signed() on anything under
# WINDOWS_DIR anyway). PowerShell 7 ships on every windows-latest runner
# under Program Files, installed as standalone software rather than
# baked into the OS image, so it's embedded-signed like the third-party
# DLLs/EXEs this function is actually meant to check.
SIGNED_THIRD_PARTY_BINARY = r"C:\Program Files\PowerShell\7\pwsh.exe"


def test_signed_third_party_binary_is_reported_as_validly_signed():
    from scanner.win_authenticode import _ERROR_SUCCESS, _verify_trust, is_signed

    # Reach into the raw WinVerifyTrust result (not just is_signed()'s bool)
    # so a failure here names the actual error code instead of just False --
    # this is the one place that can prove or disprove the ctypes struct
    # layout in scanner/win_authenticode.py against the real Win32 API.
    code = _verify_trust(SIGNED_THIRD_PARTY_BINARY)
    assert code == _ERROR_SUCCESS, (
        f"WinVerifyTrust returned 0x{code & 0xFFFFFFFF:08X} for {SIGNED_THIRD_PARTY_BINARY} "
        f"(expected 0x00000000 / ERROR_SUCCESS)"
    )
    assert is_signed(SIGNED_THIRD_PARTY_BINARY) is True


def test_is_signed_returns_false_not_an_exception_for_missing_file():
    from scanner.win_authenticode import is_signed
    assert is_signed(r"C:\nonexistent\definitely-not-real.exe") is False


def test_analyze_executable_scores_a_real_signed_binary():
    from scanner.ml.analysis import analyze_executable
    result = analyze_executable(NOTEPAD)
    assert result["ml_risk_score"] is not None
    assert 0.0 <= result["ml_risk_score"] <= 1.0
    assert result["keylogger_api_score"] is not None
    assert 0.0 <= result["keylogger_api_score"] <= 1.0
    # notepad.exe doesn't import keylogging APIs -- should score low.
    assert result["keylogger_api_score"] < 0.3


def test_detect_keyboard_hook_suspects_runs_without_crashing():
    from scanner.keyboard_hook_detector import detect_keyboard_hook_suspects
    suspects = detect_keyboard_hook_suspects()
    assert isinstance(suspects, list)


def test_scanner_main_writes_a_snapshot(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from scanner import scanner as scanner_module
    scanner_module.main()
    snapshots = os.listdir(tmp_path / "snapshots")
    assert any(f.endswith(".json") for f in snapshots)
