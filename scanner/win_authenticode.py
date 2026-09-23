"""
Direct Authenticode signature verification via WinVerifyTrust (wintrust.dll).

Replaces the previous implementation, which shelled out to
`powershell.exe -Command "(Get-AuthenticodeSignature ...).Status"` for
every unsigned-looking DLL/exe. Spawning a PowerShell process costs on
the order of 100ms-1s+ just in interpreter startup -- for every
suspicious module the scanner finds, every scan cycle -- and
Get-AuthenticodeSignature can also trigger a network revocation check by
default, adding an unbounded stall on a machine without connectivity.

WinVerifyTrust is the same Win32 API that PowerShell cmdlet calls under
the hood, invoked directly with no subprocess and no network round trip:

- WTD_UI_NONE: no popup dialogs
- WTD_REVOKE_NONE: skip revocation checking -- this tool wants "is this
  binary signed by a trusted publisher", not certificate freshness, and
  revocation checking is exactly the part that can hit the network

Results are cached per path (functools.lru_cache), same convention as
sha256() in scanner/keyboard_hook_detector.py.
"""
import ctypes
from ctypes import wintypes
from functools import lru_cache

from scanner.logger_config import setup_logger

logger = setup_logger(__name__)

# WINTRUST_ACTION_GENERIC_VERIFY_V2, {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_ACTION_GUID_FIELDS = (
    0x00AAC56B, 0xCD44, 0x11D0,
    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_ERROR_SUCCESS = 0


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.c_void_p),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _action_guid():
    data1, data2, data3, data4 = _ACTION_GUID_FIELDS
    return _GUID(data1, data2, data3, (ctypes.c_ubyte * 8)(*data4))


def _verify_trust(path):
    """
    One WinVerifyTrust call for `path`. Returns the raw LONG result code
    (0 / _ERROR_SUCCESS means a valid, trusted signature; any other value
    is a specific WinVerifyTrust/CryptoAPI error, e.g. TRUST_E_NOSIGNATURE
    0x800B0100, TRUST_E_SUBJECT_NOT_TRUSTED 0x800B0004, CERT_E_UNTRUSTEDROOT
    0x800B0109 -- kept as a raw code rather than a bool so failures are
    diagnosable instead of just "False").
    """
    wintrust = ctypes.WinDLL("wintrust.dll")
    wintrust.WinVerifyTrust.restype = wintypes.LONG
    wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p,
    ]

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WINTRUST_DATA()
    ctypes.memset(ctypes.byref(data), 0, ctypes.sizeof(data))
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    data.dwStateAction = _WTD_STATEACTION_VERIFY

    guid = _action_guid()
    result = wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))

    data.dwStateAction = _WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))

    return result


@lru_cache(maxsize=1024)
def is_signed(path):
    """Check whether a file has a valid, chain-trusted Authenticode signature."""
    try:
        result = _verify_trust(path)
        if result != _ERROR_SUCCESS:
            logger.debug(f"WinVerifyTrust for {path}: 0x{result & 0xFFFFFFFF:08X}")
        return result == _ERROR_SUCCESS
    except Exception as e:
        logger.debug(f"Signature check failed for {path}: {e}")
        return False
