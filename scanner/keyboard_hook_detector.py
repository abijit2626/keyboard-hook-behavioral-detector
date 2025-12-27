import psutil
import os
import hashlib
import subprocess
import time
from functools import lru_cache

from scanner.logger_config import setup_logger
from scanner.config import WINDOWS_DIR, ALLOWLIST

logger = setup_logger(__name__)


@lru_cache(maxsize=1024)
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


@lru_cache(maxsize=2048)
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

            import os.path
            basename = os.path.basename(exe).lower() if exe else ""
            if basename in ALLOWLIST:
                skipped_count += 1
                continue

            try:
                found_user32 = False
                suspicious_dlls = []
                for m in proc.memory_maps():
                    p = getattr(m, "path", None)
                    if not p:
                        continue
                    pl = p.lower()
                    if "user32.dll" in pl:
                        found_user32 = True
                    if pl.endswith(".dll") and not pl.startswith(WINDOWS_DIR):
                        suspicious_dlls.append({
                            "dll": p,
                            "signed": is_signed(p),
                            "hash": sha256(p)
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                logger.debug(f"Access denied or process gone for PID {pid}: {e}")
                skipped_count += 1
                continue

            if not found_user32:
                skipped_count += 1
                continue

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
