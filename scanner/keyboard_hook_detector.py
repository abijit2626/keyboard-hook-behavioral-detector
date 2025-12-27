import psutil
import os
import hashlib
import subprocess
import time

from scanner.logger_config import setup_logger

WINDOWS_DIR = os.environ.get("WINDIR", "C:\\Windows").lower()

logger = setup_logger(__name__)



def is_signed(path):
    """Check if a file has a valid digital signature."""
    try:
        # Use -LiteralPath to safely handle paths with special characters
        # Escape single quotes for PowerShell by doubling them
        escaped_path = path.replace("'", "''")
        out = subprocess.check_output(
            ["powershell", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{escaped_path}').Status"],
            stderr=subprocess.DEVNULL,
            timeout=5  # 5 second timeout
        ).decode('utf-8', errors='replace')
        return "Valid" in out
    except subprocess.TimeoutExpired:
        logger.warning(f"Signature check timed out for {path}")
        return False
    except Exception as e:
        logger.debug(f"Failed to check signature for {path}: {e}")
        return False


def sha256(path, timeout=10):
    """Calculate SHA256 hash of a file with timeout."""
    start_time = time.time()
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                if time.time() - start_time > timeout:
                    logger.warning(f"Hash calculation timeout for {path}")
                    return None
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        logger.debug(f"Permission denied reading {path} for hash")
        return None
    except Exception as e:
        logger.debug(f"Failed to calculate hash for {path}: {e}")
        return None


def detect_keyboard_hook_suspects():
    """
    Capability-based detector.
    Emits stable process identity using lifetime, not PID.
    """
    logger.debug("Starting keyboard hook detection scan")
    suspects = []
    processed_count = 0
    skipped_count = 0

    for proc in psutil.process_iter(attrs=["pid", "exe", "create_time"]):
        try:
            pid = proc.info["pid"]
            exe = proc.info["exe"]
            create_time = proc.info["create_time"]

            if not exe or not create_time:
                skipped_count += 1
                continue  # identity impossible

            try:
                modules = [m.path for m in proc.memory_maps() if m.path]
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                logger.debug(f"Access denied or process gone for PID {pid}: {e}")
                skipped_count += 1
                continue

            if not any("user32.dll" in m.lower() for m in modules):
                skipped_count += 1
                continue

            suspicious_dlls = []
            for m in modules:
                m_lower = m.lower()
                if m_lower.startswith(WINDOWS_DIR):
                    continue
                if m_lower.endswith(".dll"):
                    suspicious_dlls.append({
                        "dll": m,
                        "signed": is_signed(m),
                        "hash": sha256(m)
                    })

            entry = {
                "pid": pid,
                "executable": exe,
                "create_time": create_time
            }

            if suspicious_dlls:
                entry["type"] = "DLL_HOOK_SUSPECT"
                entry["suspicious_modules"] = suspicious_dlls
                logger.debug(
                    f"DLL_HOOK_SUSPECT: {exe} (PID: {pid}) with {len(suspicious_dlls)} suspicious DLL(s)"
                )
            else:
                if exe.lower().startswith(WINDOWS_DIR):
                    skipped_count += 1
                    continue
                entry["type"] = "EXE_HOOK_SUSPECT"
                entry["signed"] = is_signed(exe)
                entry["hash"] = sha256(exe)
                logger.debug(f"EXE_HOOK_SUSPECT: {exe} (PID: {pid})")

            suspects.append(entry)
            processed_count += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Process access error: {e}")
            skipped_count += 1
            continue

    logger.info(
        f"Detection complete: {len(suspects)} suspect(s) found, "
        f"{processed_count} processed, {skipped_count} skipped"
    )
    return suspects
