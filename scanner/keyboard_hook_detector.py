import psutil
import os
import hashlib
import time
from functools import lru_cache

from scanner.logger_config import setup_logger
from scanner.config import WINDOWS_DIR, ALLOWLIST
from scanner.ml.analysis import analyze_executable
from scanner.win_authenticode import is_signed

logger = setup_logger(__name__)


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

            analysis = analyze_executable(exe)
            if analysis["ml_risk_score"] is not None:
                entry["ml_risk_score"] = round(analysis["ml_risk_score"], 4)
                logger.debug(f"ML risk score for {exe} (PID: {pid}): {entry['ml_risk_score']:.4f}")
            if analysis["keylogger_api_score"] is not None:
                entry["keylogger_api_score"] = analysis["keylogger_api_score"]
                entry["keylogger_apis_matched"] = analysis["keylogger_apis_matched"]
                if analysis["keylogger_apis_matched"]:
                    logger.debug(
                        f"Keylogger API fingerprint for {exe} (PID: {pid}): "
                        f"{analysis['keylogger_api_score']:.4f} "
                        f"({analysis['keylogger_apis_matched']})"
                    )

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
