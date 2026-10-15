"""demo_trigger.py -- candidate DLL selection (the OS-independent part)."""
import os

import pytest

import demo_trigger


def _touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return str(path)


def test_finds_dlls_in_root_and_dlls_folder_only(tmp_path):
    a = _touch(tmp_path / "python3.dll")
    b = _touch(tmp_path / "DLLs" / "sqlite3.dll")
    _touch(tmp_path / "DLLs" / "_ctypes.pyd")   # not a .dll
    _touch(tmp_path / "Lib" / "nested.dll")     # not searched

    found = demo_trigger.find_candidate_dlls(str(tmp_path), [], windows_dir=r"c:\windows")
    assert sorted(found) == sorted([a, b])


def test_skips_already_loaded_case_insensitively(tmp_path):
    a = _touch(tmp_path / "python3.dll")
    b = _touch(tmp_path / "vcruntime140.dll")

    found = demo_trigger.find_candidate_dlls(str(tmp_path), [a.upper()], windows_dir=r"c:\windows")
    assert found == [b]


def test_skips_dlls_under_the_windows_directory(tmp_path):
    _touch(tmp_path / "python3.dll")
    windows_dir = str(tmp_path).lower()  # pretend the install lives under WINDIR

    assert demo_trigger.find_candidate_dlls(str(tmp_path), [], windows_dir=windows_dir) == []


def test_missing_folders_are_ignored(tmp_path):
    assert demo_trigger.find_candidate_dlls(str(tmp_path / "nope"), []) == []


@pytest.mark.skipif(os.name == "nt", reason="the off-Windows guard only runs off Windows")
def test_exits_cleanly_off_windows(capsys):
    assert demo_trigger.main([]) == 1
    assert "Windows-only" in capsys.readouterr().out
