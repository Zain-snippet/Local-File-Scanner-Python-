# module3_script_analyzer

import os
import re
from datetime import datetime

from module10_shared_utils import (
    format_timestamp
)
    # ---------------------------
    # ----- Calculate script Risk
    #----------------------------
    
def calculate_script_risk(signals):
    """
    Calculate risk score and severity based on intent signals.
    """

    # ---------------- Base Risk Weights ----------------
    BASE_WEIGHTS = {
        "payload_download": 40,
        "persistence": 35,
        "destructive_ops": 30,
        "obfuscation": 15
    }

    # ---------------- Escalation Rules ----------------
    ESCALATIONS = [
        ({"payload_download", "obfuscation"}, 25),
        ({"payload_download", "persistence"}, 30),
        ({"persistence", "obfuscation"}, 20),
        ({"destructive_ops", "obfuscation"}, 20)
    ]

    risk_score = 0
    triggered = set()

    # Apply base weights
    for category, active in signals.items():
        if active:
            risk_score += BASE_WEIGHTS.get(category, 0)
            triggered.add(category)

    # Apply escalation bonuses
    for combo, bonus in ESCALATIONS:
        if combo.issubset(triggered):
            risk_score += bonus

    # ---------------- Severity Mapping ----------------
    if risk_score == 0:
        severity = "None"
    elif risk_score < 30:
        severity = "Low"
    elif risk_score < 60:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "triggered_categories": sorted(triggered)
    }


# --------------------------------------------------
# Check if script
# --------------------------------------------------


SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".js", ".vbs", ".sh", ".py"
}

MAX_SCRIPT_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


def is_script_candidate(filepath):
    """
    Decide whether a file is eligible for script analysis.
    Silent skip on failure.
    """

    try:
        # Extension gate
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in SCRIPT_EXTENSIONS:
            return False

        # Size gate
        size = os.path.getsize(filepath)
        if size == 0 or size > MAX_SCRIPT_SIZE_BYTES:
            return False

        # Binary content rejection (read small chunk)
        with open(filepath, "rb") as f:
            sample = f.read(2048)
            if b"\x00" in sample:
                return False

        return True

    except Exception:
        # Any access/IO issue → silently skip
        return False


# --------------------------------------------------
# read script
# --------------------------------------------------

def read_script_safely(filepath):
    """
    Read script content with encoding awareness.
    Returns None if unreadable.
    """

    ext = os.path.splitext(filepath)[1].lower()

    try:
        # PowerShell often uses UTF-16
        if ext == ".ps1":
            try:
                with open(filepath, "r", encoding="utf-16") as f:
                    return f.read()
            except UnicodeError:
                pass  # fall through

        # Default: UTF-8 with fallback
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            return content if content.strip() else None

    except Exception:
        return None


# --------------------------------------------------
# Main Orchestrator
# --------------------------------------------------

def analyze_script(path, command_db):
    # ---------- Eligibility ----------
    if not is_script_candidate(path):
        return None

    content = read_script_safely(path)
    if not content:
        return None

    # ---------- Run detectors ----------
    obf_hits = detect_obfuscation(content)
    cmd_hits = scan_for_dangerous_commands(content, command_db)
    net_hits = check_network_activity(content)
    reg_hits = check_registry_manipulation(content)
    file_hits = check_file_operations(content)

    # ---------- Align to intent signals ----------

    signals = {
    "payload_download": bool(cmd_hits or net_hits),
    "persistence": bool(reg_hits),
    "obfuscation": obf_hits.get("is_obfuscated", False),
    "destructive_ops": bool(file_hits)
    }


    # ---------- Risk scoring ----------
    risk = calculate_script_risk(signals)

    # ---------- Ignore harmless scripts ----------
    if risk["risk_score"] == 0:
        return None

    # ---------- Final result ----------
    return {
        "type": "script",
        "path": path,
        "name": os.path.basename(path),
        "timestamp": format_timestamp(datetime.now()),
        "severity": risk["severity"],
        "risk_score": risk["risk_score"],
        "triggered_categories": risk["triggered_categories"],
        "findings": {
            "obfuscation": obf_hits,
            "dangerous_commands": cmd_hits,
            "network_activity": net_hits,
            "registry_activity": reg_hits,
            "file_operations": file_hits
        },
        "issues": [
            f"Suspicious script behavior detected ({', '.join(risk['triggered_categories'])})"
        ]
    }




# --------------------------------------------------
# Obfuscation Detection
# --------------------------------------------------


def detect_obfuscation(content):
    """
    Detects obfuscation patterns in script content.
    Returns structured signal.
    """

    # ---------- Hard stop for empty / trivial content ----------
    if not content or not content.strip():
        return {
            "is_obfuscated": False,
            "base64_detected": False,
            "hex_sequences": False,
            "string_concat": False
        }

    # Too short to be meaningful obfuscation
    if len(content.strip()) < 30:
        return {
            "is_obfuscated": False,
            "base64_detected": False,
            "hex_sequences": False,
            "string_concat": False
        }

    base64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
    hex_pattern = re.compile(r"(?:0x[a-fA-F0-9]{2,})")
    concat_pattern = re.compile(r"(\".*?\"\s*\+\s*){2,}")

    base64_found = bool(base64_pattern.search(content))
    hex_found = bool(hex_pattern.search(content))
    concat_found = bool(concat_pattern.search(content))

    is_obfuscated = base64_found or hex_found or concat_found

    return {
        "is_obfuscated": is_obfuscated,
        "base64_detected": base64_found,
        "hex_sequences": hex_found,
        "string_concat": concat_found
    }



# --------------------------------------------------
# Dangerous Commands
# --------------------------------------------------

def scan_for_dangerous_commands(text, command_db):
    findings = []

    for pat in command_db:
        for match in re.finditer(pat, text, re.IGNORECASE):
            findings.append({
                "pattern": pat,
                "match": match.group(0)
            })

    return findings



# --------------------------------------------------
# Network Activity
# --------------------------------------------------

def check_network_activity(text):
    if not text:
        return []

    findings = []

    url_pat = r'https?://[^\s]+'
    ip_pat = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    for u in re.findall(url_pat, text):
        findings.append({"type": "url", "value": u})

    for ip in re.findall(ip_pat, text):
        if ip not in ("127.0.0.1", "0.0.0.0"):
            findings.append({"type": "ip", "value": ip})

    return findings


# --------------------------------------------------
# Registry Manipulation
# --------------------------------------------------

def check_registry_manipulation(text):
    if not text:
        return []

    patterns = [
        r'\breg\s+add\b',
        r'\breg\s+delete\b',
        r'HKLM\\',
        r'HKCU\\'
    ]

    findings = []

    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({
                "pattern": pat,
                "severity": "High"
            })

    return findings


# --------------------------------------------------
# File Operations
# --------------------------------------------------

def check_file_operations(text):
    if not text:
        return []

    patterns = [
        r'\bdel\b',
        r'\brm\b',
        r'\bRemove-Item\b',
        r'\bcopy\b',
        r'\bmove\b'
    ]

    findings = []

    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({
                "operation": pat,
                "severity": "Medium"
            })

    return findings




