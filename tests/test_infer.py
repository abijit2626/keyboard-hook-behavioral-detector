"""
scanner/ml/infer.py -- standalone inference CLI.

Needs real PE files, and CI's Linux runner has none, so these build a
minimal but genuine PE32 in memory (real headers + a real import table)
and run it through the whole pipeline -- pefile parse, ClaMP feature
extraction, the trained RandomForest, the import-table fingerprint.
Nothing here is mocked except where a test says so.
"""
import json
import os
import struct

import pytest

from scanner.ml import infer


def build_pe(imports=()):
    """Minimal valid PE32 whose one section holds an import table for `imports` (user32.dll)."""
    section_rva, file_align, sect_align = 0x1000, 0x200, 0x1000
    n = len(imports)

    # Section layout: [import descriptors][ILT][IAT][dll name][hint/name entries]
    desc_off = 0
    ilt_off = desc_off + 2 * 20
    iat_off = ilt_off + (n + 1) * 4
    dll_off = iat_off + (n + 1) * 4
    dll_name = b"user32.dll\x00"
    hn_off = dll_off + len(dll_name)

    hint_names, hn_rvas, cursor = b"", [], hn_off
    for name in imports:
        entry = struct.pack("<H", 0) + name.encode() + b"\x00"
        entry += b"\x00" * (len(entry) % 2)
        hn_rvas.append(section_rva + cursor)
        hint_names += entry
        cursor += len(entry)

    thunks = b"".join(struct.pack("<I", rva) for rva in hn_rvas) + struct.pack("<I", 0)
    descriptors = b""
    if n:
        descriptors = struct.pack(
            "<IIIII", section_rva + ilt_off, 0, 0, section_rva + dll_off, section_rva + iat_off
        )
    descriptors += b"\x00" * 20  # terminator
    body = descriptors.ljust(ilt_off, b"\x00") + thunks + thunks + dll_name + hint_names
    assert len(body) <= file_align
    body = body.ljust(file_align, b"\x00")

    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0x5A000000, 0, 0, 0xE0, 0x0102)
    data_dirs = [(0, 0)] * 16
    if n:
        data_dirs[1] = (section_rva + desc_off, 40)
    optional = (
        struct.pack("<HBB", 0x10B, 14, 0)  # Magic (PE32), linker version
        # SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData,
        # AddressOfEntryPoint, BaseOfCode, BaseOfData
        + struct.pack("<IIIIII", file_align, 0, 0, section_rva, section_rva, 0)
        + struct.pack("<III", 0x400000, sect_align, file_align)  # ImageBase, alignments
        + struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)  # OS / image / subsystem versions
        + struct.pack("<IIII", 0, 0x2000, file_align, 0)  # Win32Version, SizeOfImage, SizeOfHeaders, CheckSum
        + struct.pack("<HH", 3, 0x8140)  # Subsystem, DllCharacteristics
        + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # stack / heap reserve+commit
        + struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
        + b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)
    )
    section = struct.pack(
        "<8sIIIIIIHHI", b".text", file_align, section_rva, file_align, file_align,
        0, 0, 0, 0, 0x60000020,
    )
    header = dos + b"PE\x00\x00" + file_header + optional + section
    return header.ljust(file_align, b"\x00") + body


HOOKY_IMPORTS = ["SetWindowsHookExW", "GetAsyncKeyState", "GetForegroundWindow"]


@pytest.fixture
def hooky_exe(tmp_path):
    path = tmp_path / "hooky.exe"
    path.write_bytes(build_pe(HOOKY_IMPORTS))
    return str(path)


@pytest.fixture
def plain_exe(tmp_path):
    path = tmp_path / "plain.exe"
    path.write_bytes(build_pe(["MessageBoxW"]))
    return str(path)


def test_infer_file_scores_both_layers_on_a_real_pe(hooky_exe):
    result = infer.infer_file(hooky_exe)

    assert result["scored"] is True
    assert result["path"] == hooky_exe
    assert 0.0 <= result["ml_risk_score"] <= 1.0
    assert set(result["keylogger_apis_matched"]) == {
        "low_level_hook", "keystate_polling", "window_tracking",
    }
    # 0.40 + 0.18 + 0.02 of a 0.99 total.
    assert result["keylogger_api_score"] == pytest.approx(0.6061, abs=1e-3)


def test_keylogger_score_separates_hooky_from_plain_imports(hooky_exe, plain_exe):
    plain = infer.infer_file(plain_exe)

    assert plain["scored"] is True
    assert plain["keylogger_apis_matched"] == []
    assert plain["keylogger_api_score"] == 0.0
    assert infer.infer_file(hooky_exe)["keylogger_api_score"] > plain["keylogger_api_score"]


def test_infer_file_marks_non_pe_as_not_scored(tmp_path):
    junk = tmp_path / "notes.exe"
    junk.write_bytes(b"definitely not a PE file")

    result = infer.infer_file(str(junk))

    assert result["scored"] is False
    assert result["ml_risk_score"] is None
    assert result["keylogger_api_score"] is None


def test_collect_targets_walks_dirs_for_pe_extensions_only(tmp_path):
    (tmp_path / "sub").mkdir()
    for rel in ["a.exe", "sub/b.DLL", "sub/c.txt", "d.sys"]:
        (tmp_path / rel).write_bytes(b"x")
    explicit = tmp_path / "script.bin"  # no PE extension, but named explicitly
    explicit.write_bytes(b"x")

    files, missing = infer.collect_targets(
        [str(tmp_path), str(explicit), str(tmp_path / "a.exe"), str(tmp_path / "gone.exe")]
    )

    names = [os.path.relpath(f, tmp_path).replace(os.sep, "/") for f in files]
    # c.txt skipped; a.exe is listed once even though it's reachable twice.
    assert names == ["a.exe", "d.sys", "sub/b.DLL", "script.bin"]
    assert missing == [str(tmp_path / "gone.exe")]


def test_main_json_output(hooky_exe, plain_exe, capsys):
    code = infer.main([hooky_exe, plain_exe, "--json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert {d["path"] for d in data} == {hooky_exe, plain_exe}
    assert all(d["scored"] for d in data)


def test_render_table_sorts_highest_malware_score_first(capsys):
    def row(path, ml):
        return {"path": path, "scored": True, "ml_risk_score": ml,
                "keylogger_api_score": 0.0, "keylogger_apis_matched": []}

    infer.render_table([row("low.exe", 0.1), row("high.exe", 0.9), row("mid.exe", 0.5)])
    out = capsys.readouterr().out

    assert out.index("high.exe") < out.index("mid.exe") < out.index("low.exe")
    assert "90%" in out and "3 scored, 0 skipped." in out


def test_main_table_shows_scores_and_reports_skipped(hooky_exe, tmp_path, capsys):
    junk = tmp_path / "junk.dll"
    junk.write_bytes(b"nope")

    code = infer.main([hooky_exe, str(junk)])
    out = capsys.readouterr().out

    assert code == 1  # something couldn't be scored
    assert "MALWARE ML" in out and "low_level_hook" in out
    assert f"skipped (not a parsable PE file): {junk}" in out
    assert "1 scored, 1 skipped." in out


def test_main_fails_on_missing_path(capsys):
    code = infer.main(["/definitely/not/here.exe"])

    assert code == 1
    assert "no such file or directory" in capsys.readouterr().err


def test_main_fails_clearly_when_model_is_missing(hooky_exe, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(infer, "MODEL_PATH", str(tmp_path / "no_model.joblib"))

    code = infer.main([hooky_exe])

    assert code == 1
    assert "python train_model.py" in capsys.readouterr().err
