import sys
import time
import ctypes
from ctypes import wintypes
import os

# Define Windows API constants and types
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, ctypes.c_void_p)

user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, wintypes.WPARAM, ctypes.c_void_p]
user32.CallNextHookEx.restype = ctypes.c_int

def hook_proc(nCode, wParam, lParam):
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

pointer = HOOKPROC(hook_proc)

def main():
    print(f"PID: {os.getpid()}")
    print("Installing dummy keyboard hook...")
    
    # Install the low-level keyboard hook
    # GetModuleHandleW(None) gets the handle to the current process (python.exe)
    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
    user32.SetWindowsHookExW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetLastError.restype = wintypes.DWORD

    try:
        hmod = kernel32.GetModuleHandleW(None)
        hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, pointer, hmod, 0)
    except Exception as e:
        print(f"Failed to install hook: {e}")
        return

    if not hook:
        err = kernel32.GetLastError()
        print(f"Failed to install hook (error {err}). Try running PowerShell as Administrator and ensure 64-bit Python.")
        return

    print("Hook installed. This process is now acting like a keylogger.")
    print("The detector should identify it as a suspect due to behavior and loaded modules.")
    print("Press Ctrl+C to stop.")

    # Windows message loop is required for hooks to work
    msg = wintypes.MSG()
    try:
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if hook:
            user32.UnhookWindowsHookEx(hook)
            print("Hook removed.")

if __name__ == "__main__":
    main()