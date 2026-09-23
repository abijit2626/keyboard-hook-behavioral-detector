"""
Static PE-header feature extraction.

Reimplements (for modern Python 3 + pefile) the feature set used by the
ClaMP ("Classification of Malware with PE headers") dataset's
integrated_features_extraction.py, so the model trained on that real,
public dataset in scanner/ml/data/clamp_integrated.csv can be applied to
real executables/DLLs at scan time using the exact same feature space.

Source dataset / original extraction logic:
  https://github.com/urwithajit9/ClaMP (Ajit Kumar) -- "No license
  required for any kind of reuse" per the scripts' own header comments.

Two of the original 69 columns, 'packer' and 'packer_type', are dropped
here (and at training time): they require a PEiD signature database
compiled as YARA rules, which this project does not bundle. Everything
else -- all 67 remaining raw + derived PE header features -- is computed
directly from the file via pefile, matching the original definitions.
"""
import math
from collections import Counter

import pefile

FEATURE_NAMES = [
    "e_cblp", "e_cp", "e_cparhdr", "e_maxalloc", "e_sp", "e_lfanew",
    "NumberOfSections", "CreationYear",
] + [f"FH_char{i}" for i in range(15)] + [
    "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
    "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
    "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment",
    "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
    "MajorImageVersion", "MinorImageVersion",
    "MajorSubsystemVersion", "MinorSubsystemVersion",
    "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem",
] + [f"OH_DLLchar{i}" for i in range(11)] + [
    "SizeOfStackReserve", "SizeOfStackCommit",
    "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags",
] + [
    "sus_sections", "non_sus_sections",
    "E_text", "E_data", "filesize", "E_file", "fileinfo",
]

# Bit masks for FILE_HEADER.Characteristics, in the exact order ClaMP uses
# (ascending bit value, skipping the one reserved bit 0x0040).
_FH_CHAR_MASKS = [
    0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0080, 0x0100,
    0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
]

# Bit masks for OPTIONAL_HEADER.DllCharacteristics, in ClaMP's own order.
_OH_DLLCHAR_MASKS = [
    0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800,
    0x2000, 0x8000, 0x0020, 0x1000, 0x4000,
]

_BENIGN_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".bss", ".crt", ".tls",
}


def _file_creation_year_flag(timestamp):
    """1 if the PE timestamp decodes to a year in [1980, 2016), else 0."""
    try:
        year = 1970 + ((int(timestamp) / 86400) / 365)
        return int(1980 <= year < 2016)
    except (ValueError, OverflowError):
        return 0


def _image_base_flag(image_base):
    return int(
        image_base % (64 * 1024) == 0
        and image_base in (268435456, 65536, 4194304)
    )


def _section_alignment_flag(section_alignment, file_alignment):
    return int(section_alignment >= file_alignment)


def _file_alignment_flag(section_alignment, file_alignment):
    if section_alignment >= 512:
        return int(file_alignment % 2 == 0 and 512 <= file_alignment <= 65536)
    return int(file_alignment == section_alignment)


def _size_of_image_flag(size_of_image, section_alignment):
    return int(section_alignment != 0 and size_of_image % section_alignment == 0)


def _size_of_headers_flag(size_of_headers, file_alignment):
    return int(file_alignment != 0 and size_of_headers % file_alignment == 0)


def _section_name(section):
    return section.Name.split(b"\x00")[0].decode("latin-1")


def _suspicious_section_counts(pe):
    names = [_section_name(s) for s in pe.sections]
    non_sus = len(set(names) & _BENIGN_SECTION_NAMES)
    return len(names) - non_sus, non_sus


def _text_data_entropy(pe):
    text_entropy = data_entropy = 0.0
    for section in pe.sections:
        name = _section_name(section)
        if name == ".text":
            text_entropy = section.get_entropy()
        elif name == ".data":
            data_entropy = section.get_entropy()
    return text_entropy, data_entropy


def _file_size_and_entropy(pe, filepath):
    """
    Whole-file size + Shannon entropy. Reuses the bytes pefile already
    read into `pe.__data__` (an mmap, verified to match the file exactly)
    instead of a second full read of the file from disk -- filepath is
    only a fallback for when a raw pe object isn't available.
    """
    data = getattr(pe, "__data__", None)
    if data is None:
        with open(filepath, "rb") as f:
            data = f.read()
    size = len(data)
    if size == 0:
        return 0, 0.0
    counts = Counter(data)
    entropy = -sum(
        (c / size) * math.log2(c / size) for c in counts.values()
    )
    return size, entropy


def _has_version_info(pe):
    try:
        pe.FileInfo[0].StringTable[0].entries["FileVersion"]
        pe.VS_FIXEDFILEINFO.FileVersionLS
        return 1
    except Exception:
        return 0


def extract_features_from_pe(pe, filepath=None):
    """
    Extract the 67-element ClaMP-compatible feature vector from an
    already-open `pefile.PE` instance (RESOURCE directory must already be
    parsed -- see scanner/ml/analysis.py, which shares one `pe` across
    both ML layers instead of parsing the file twice).

    Returns a list[float] in FEATURE_NAMES order, or None on failure.
    """
    try:
        dos = [
            pe.DOS_HEADER.e_cblp, pe.DOS_HEADER.e_cp, pe.DOS_HEADER.e_cparhdr,
            pe.DOS_HEADER.e_maxalloc, pe.DOS_HEADER.e_sp, pe.DOS_HEADER.e_lfanew,
        ]

        file_hdr = [
            pe.FILE_HEADER.NumberOfSections,
            _file_creation_year_flag(pe.FILE_HEADER.TimeDateStamp),
        ]
        characteristics = pe.FILE_HEADER.Characteristics
        fh_char = [int(bool(characteristics & mask)) for mask in _FH_CHAR_MASKS]

        oh = pe.OPTIONAL_HEADER
        section_alignment = oh.SectionAlignment
        file_alignment = oh.FileAlignment
        optional_hdr = [
            oh.MajorLinkerVersion, oh.MinorLinkerVersion, oh.SizeOfCode,
            oh.SizeOfInitializedData, oh.SizeOfUninitializedData,
            oh.AddressOfEntryPoint, oh.BaseOfCode,
            getattr(oh, "BaseOfData", 0),
            _image_base_flag(oh.ImageBase),
            _section_alignment_flag(section_alignment, file_alignment),
            _file_alignment_flag(section_alignment, file_alignment),
            oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion,
            oh.MajorImageVersion, oh.MinorImageVersion,
            oh.MajorSubsystemVersion, oh.MinorSubsystemVersion,
            _size_of_image_flag(oh.SizeOfImage, section_alignment),
            _size_of_headers_flag(oh.SizeOfHeaders, file_alignment),
            oh.CheckSum, oh.Subsystem,
        ]
        dll_characteristics = oh.DllCharacteristics
        dll_char = [int(bool(dll_characteristics & mask)) for mask in _OH_DLLCHAR_MASKS]

        optional_hdr2 = [
            oh.SizeOfStackReserve, oh.SizeOfStackCommit,
            oh.SizeOfHeapReserve, oh.SizeOfHeapCommit,
            int(oh.LoaderFlags == 0),
        ]

        sus, non_sus = _suspicious_section_counts(pe)
        text_entropy, data_entropy = _text_data_entropy(pe)
        filesize, file_entropy = _file_size_and_entropy(pe, filepath)
        fileinfo = _has_version_info(pe)

        return [float(v) for v in (
            dos + file_hdr + fh_char + optional_hdr + dll_char + optional_hdr2
            + [sus, non_sus, text_entropy, data_entropy, filesize, file_entropy, fileinfo]
        )]
    except Exception:
        return None


def extract_pe_features(filepath):
    """
    Standalone convenience wrapper: open `filepath`, parse the RESOURCE
    directory, extract features, close. For callers that don't already
    have an open `pe` object (training/debugging use); the live scan
    path uses scanner/ml/analysis.py instead, which shares one `pe`
    across both ML layers.
    """
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
    except Exception:
        return None
    try:
        return extract_features_from_pe(pe, filepath)
    finally:
        pe.close()
