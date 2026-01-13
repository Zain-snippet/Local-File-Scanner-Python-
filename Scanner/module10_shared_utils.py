from datetime import datetime
import hashlib
import re
import os


# ---------------- Logging ----------------

def log_message(level, message):
    """
    Central logging utility.
    Logging must NEVER crash the program.
    """
    try:
        timestamp = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
        lvl = str(level).upper() if level else "INFO"
        msg = str(message)
        print(f"[{timestamp}] [{lvl}] {msg}")
    except Exception:
        pass

   # ------------- format time ----------

def format_timestamp(ts):
    """
    Convert various timestamp formats to a readable string.
    """
    try:
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %I:%M:%S %p")

        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %I:%M:%S %p")

        if isinstance(ts, str):
            return ts.strip()
    except Exception:
        pass

    return None


# ---------------- Path Validation ----------------

def validate_filepath(path):
    """
    Validate, normalize, and verify a filesystem path.

    Returns:
        str -> absolute normalized path (existing file)
        None -> invalid / non-existent / inaccessible
    """
    if not isinstance(path, str):
        return None

    path = path.strip()
    if not path:
        return None

    try:
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        path = os.path.abspath(os.path.normpath(path))

        if not os.path.exists(path):
            return None

        return path
    except Exception:
        return None


# ---------------- File Utilities ----------------

def safe_file_read(filepath):
    """
    Safely read a file's contents.
    """
    path = validate_filepath(filepath)
    if not path or not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


# --------- human readable path ''''


def human_readable_path(path: str, max_length: int = 60) -> str:
    path = path.replace("\\", "/")

    if len(path) <= max_length:
        return path

    parts = path.split("/")
    if len(parts) <= 2:
        return path[-max_length:]

    return f"{parts[0]}/.../{parts[-1]}"
