# model_executable_detector

import os
from datetime import datetime

    # --------- detect_fake_extension ----------

    # --------- detect_fake_extension ----------

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".com"
}

DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".zip", ".rar", ".7z",
    ".txt", ".sslog"
}


def detect_fake_extension(filepath):
    """
    Detect fake / double extension executables like:
    invoice.pdf.exe
    photo.jpg.scr
    """

    filename = os.path.basename(filepath).lower()
    
    # Split filename into parts (ignore directory dots)
    parts = filename.split(".")

    # Must have at least: name.decoy.exe
    if len(parts) < 3:
        return None

    # Normalize extensions WITH dot
    final_ext = "." + parts[-1]
    inner_exts = ["." + ext for ext in parts[1:-1]]

    # Final extension must be executable
    if final_ext not in EXECUTABLE_EXTENSIONS:
        return None

    # Any inner extension matching decoy list?
    for ext in inner_exts:
        if ext in DECOY_EXTENSIONS:
            return {
                "type": "executable",
                "path": filepath,
                "name": filename,
                "timestamp": datetime.now().isoformat(),
                "severity": "High",
                "risk_score": 80,
                "issues": [
                    f"Fake extension detected: {ext} disguised as {final_ext}"
                ]
            }

    return None


        #---------- detect_suspicious_location ---------- #

# Tiered suspicious locations
HIGH_RISK_LOCATIONS = [
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\local\\temp\\",
    "\\temp\\"
]

MEDIUM_RISK_LOCATIONS = [
    "\\documents\\",
    "\\pictures\\",
    "\\videos\\"
]

SAFE_LOCATIONS = [
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\",
    "\\windows\\system32\\"
]


def detect_suspicious_location(filepath):
    """
    Detect executables stored in suspicious locations.
    """
    
    path = os.path.abspath(filepath).lower()
    _, ext = os.path.splitext(path)

    # Apply only to executables
    if ext not in EXECUTABLE_EXTENSIONS:
        return None

    # Ignore safe locations
    for safe in SAFE_LOCATIONS:
        if safe in path:
            return None

    # High-risk locations
    for loc in HIGH_RISK_LOCATIONS:
        if loc in path:
            return {
                "type": "executable",
                "path": filepath,
                "name": os.path.basename(filepath),
                "timestamp": datetime.now().isoformat(),
                "severity": "Medium",
                "risk_score": 40,
                "issues": [
                    f"Executable located in high-risk directory ({loc.strip('\\\\')})"
                ]
            }

    # Medium-risk locations
    for loc in MEDIUM_RISK_LOCATIONS:
        if loc in path:
            return {
                "type": "executable",
                "path": filepath,
                "name": os.path.basename(filepath),
                "timestamp": datetime.now().isoformat(),
                "severity": "Low",
                "risk_score": 20,
                "issues": [
                    f"Executable located in unusual directory ({loc.strip('\\\\')})"
                ]
            }

    return None


# =====    detect_executable_type_mismatch   =====

# Extensions users trust as non-executables
NON_EXECUTABLE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf"
}


def detect_executable_type_mismatch(filepath):
    """
    Detect files whose extension suggests a document/image,
    but whose binary header indicates a Windows executable (MZ).
    """

    #("Executing type Mismatch")

    path = os.path.abspath(filepath)
    _, ext = os.path.splitext(path.lower())

    # Only check trusted non-executable extensions
    if ext not in NON_EXECUTABLE_EXTENSIONS:
        return None

    try:
        with open(path, "rb") as f:
            header = f.read(2)
    except Exception:
        return None  # unreadable files are ignored safely

    # Windows executables start with 'MZ'
    if header == b"MZ":
        return {
            "type": "executable",
            "path": filepath,
            "name": os.path.basename(filepath),
            "timestamp": datetime.now().isoformat(),
            "severity": "High",
            "risk_score": 70,
            "issues": [
                "File extension does not match executable file type (MZ header detected)"
            ]
        }

    return None
