# module2_file_scanner.py

import os
import platform
from datetime import datetime

from module10_shared_utils import (
    log_message,
    validate_filepath,
)

# -------------------------------------------------
# Core: Directory Scanner
# -------------------------------------------------

def scan_directory(path, include_hidden=False, follow_symlinks=False):
    """
    Recursively scan a directory and return a list of valid file paths.
    """

    file_list = []

    if not os.path.isdir(path):
        log_message("WARNING", f"Invalid scan path: {path}")
        return file_list

    for root, dirs, files in os.walk(path, followlinks=follow_symlinks):

        # filter hidden directories
        if not include_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            if not include_hidden and filename.startswith("."):
                continue

            full_path = os.path.join(root, filename)

            try:
                if validate_filepath(full_path):
                    file_list.append(full_path)
            except Exception:
                continue

    return file_list


#==========================
# Categorize
# ===================
def categorize_file(filepath):
    """
    Categorize file by extension only (fast & predictable).
    """

    ext = os.path.splitext(filepath)[1].lower()

    if ext in {".exe", ".dll", ".sys", ".com"}:
        return "executable"
    elif ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}:
        return "script"
    elif ext in {".zip", ".rar", ".7z", ".tar", ".gz"}:
        return "archive"
    elif ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
        return "document"
    else:
        return "other"



# -------------------------------------------------
# Metadata
# -------------------------------------------------

def get_file_metadata(filepath):
    """
    Build structured metadata for a file.
    """

    try:
        stats = os.stat(filepath)

        return {
            "path": filepath,
            "size": stats.st_size,
            "extension": os.path.splitext(filepath)[1].lower(),
            "type": categorize_file(filepath),
            "hidden": is_hidden(filepath),
        }


    except Exception as e:
        log_message("ERROR", f"Metadata error for {filepath}: {e}")
        return None


def build_file_inventory(file_paths):
    """
    Convert list of file paths into structured inventory.
    """

    inventory = []

    for path in file_paths:
        meta = get_file_metadata(path)
        if meta:
            inventory.append(meta)

    return inventory


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def is_hidden(path):
    """
    Cross-platform hidden file detection.
    """

    name = os.path.basename(path)

    # Unix-style
    if name.startswith(".") and name not in {".", ".."}:
        return True

    # Windows attribute check
    if platform.system() == "Windows":
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
            return bool(attrs & 0x2)
        except Exception:
            return False

    return False


def is_system_directory(path):
    """
    Identify system directories to avoid scanning.
    """

    path = os.path.normpath(path).lower()

    SYSTEM_DIRS = {
        "c:\\windows",
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\programdata",
        "c:\\$recycle.bin",
        "c:\\system volume information",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
    }

    return any(path.startswith(d) for d in SYSTEM_DIRS)
