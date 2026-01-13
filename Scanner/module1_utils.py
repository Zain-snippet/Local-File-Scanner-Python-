# module1_utils.py
# File-related helper utilities used across the scanner

import os

from module10_shared_utils import log_message



# -------------------------------------------------
# File Validation
# -------------------------------------------------

def validate_filepath(path: str) -> bool:
    return (
        isinstance(path, str)
        and os.path.exists(path)
        and os.path.isfile(path)
        and os.access(path, os.R_OK)
    )


# -------------------------------------------------
# Safe File Read
# -------------------------------------------------

def safe_file_read(path: str, max_size: int):
    if not validate_filepath(path):
        return None

    try:
        if os.path.getsize(path) > max_size:
            log_message("WARNING", f"File too large to read: {path}")
            return None

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        log_message("ERROR", f"Failed to read file {path}: {e}")
        return None

