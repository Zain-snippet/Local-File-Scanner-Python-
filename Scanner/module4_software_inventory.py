# module4_software_inventory.py

from module10_shared_utils import log_message
from module5_vulnerability_manager import normalize_version_string

from datetime import datetime
import platform

# Windows-only imports guarded
if platform.system() == "Windows":
    import winreg


# =========================
# PUBLIC ENTRY POINT
# =========================

def build_software_inventory():
    if platform.system() != "Windows":
        log_message("INFO", "Software inventory skipped (non-Windows OS)")
        return []

    log_message("INFO", "Building software inventory")

    try:
        raw_entries = parse_uninstall_keys()
    except Exception as e:
        log_message("ERROR", f"Failed to read uninstall keys: {e}")
        return []

    processed = []

    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue

        enriched = process_software_entry(entry)
        if not isinstance(enriched, dict):
            continue

        name = enriched.get("name")
        version = enriched.get("version")

        if not isinstance(name, str) or not name.strip():
            continue

        if not isinstance(version, list) or not version:
            continue

        processed.append(enriched)

    log_message("INFO", "Software inventory complete ")
 

    
    return sorted(processed, key=lambda x: x["name"].lower())


# =========================
# PROCESSING
# =========================
def process_software_entry(raw):
    try:
        name = raw.get("name", "Unknown")
        raw_version = raw.get("version")

        normalized_version = normalize_version_string(raw_version)
        if not isinstance(normalized_version, list):
            return None   # skip unparseable versions

        entry = {
            "name": name,
            "version": normalized_version,   
            "raw_version": raw_version,
            "publisher": extract_publisher_info(raw),
            "publisher_risk": get_publisher_risk_level(
                extract_publisher_info(raw)
            ),
            "install_path": raw.get("install_location", "Unknown"),
            "registry_key": raw.get("subkey_name", "Unknown"),
            "install_date": extract_install_date(raw),
            "uninstall_string": raw.get("uninstall_string", "Unknown"),
            "valid": validate_software_entry(name)
        }

        return entry

    except Exception as e:
        log_message("WARNING", f"Failed processing software entry: {e}")
        return None


#=======================
# validate_software_entry
#=========================

def validate_software_entry(name):
    if not name or name.lower() == "unknown":
        return False

    blacklist = [
        "update for", "security update", "hotfix",
        "kb", "redistributable", "uninstall"
    ]

    lname = name.lower()
    return not any(bad in lname for bad in blacklist)


# =========================
# REGISTRY PARSING
# =========================


def parse_uninstall_keys():
    entries = []

    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in locations:
        entries.extend(query_windows_registry(hive, path))

    return remove_duplicates(entries)



def query_windows_registry(hive, key_path):
    results = []

    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        count = winreg.QueryInfoKey(key)[0]

        for i in range(count):
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(hive, f"{key_path}\\{subkey_name}")

                entry = {
                    "subkey_name": subkey_name,
                    "name": read_registry_value(subkey, "DisplayName"),
                    "version": read_registry_value(subkey, "DisplayVersion"),
                    "publisher": read_registry_value(subkey, "Publisher"),
                    "install_location": read_registry_value(subkey, "InstallLocation"),
                    "uninstall_string": read_registry_value(subkey, "UninstallString"),
                    "InstallDate": read_registry_value(subkey, "InstallDate")
                }

                if entry["name"]:
                    results.append(entry)

                winreg.CloseKey(subkey)

            except Exception:
                continue

        winreg.CloseKey(key)

    except Exception as e:
        log_message("WARNING", f"Registry read failed: {e}")

    return results

# ==============
# Read EReg Value
# ===============

def read_registry_value(key, value):
    try:
        val, _ = winreg.QueryValueEx(key, value)
        return str(val).strip() if val else None
    except Exception:
        return None

# ===============####
# Duplication REmoval 
# ====================
def remove_duplicates(entries):
    seen = set()
    unique = []

    for e in entries:
        if not isinstance(e, dict):
            continue

        name = e.get("name")
        version = e.get("version")

        if not isinstance(name, str) or not isinstance(version, str):
            continue

        key = (name.strip().lower(), version.strip().lower())

        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique



# =========================
# METADATA HELPERS
# =========================

def extract_install_date(raw):
    val = raw.get("InstallDate")
    if not val:
        return "Unknown"

    try:
        s = str(val)
        return datetime(int(s[:4]), int(s[4:6]), int(s[6:8])).strftime("%Y-%m-%d")
    except Exception:
        return "Unknown"


def extract_publisher_info(raw):
    pub = raw.get("publisher")
    if not pub:
        return "Unknown"

    pub = str(pub).strip()
    if pub.lower() in {"unknown", "n/a", "-", ""}:
        return "Unknown"

    return pub


def get_publisher_risk_level(publisher):
    if publisher == "Unknown":
        return "High"

    trusted = [
        "microsoft", "google", "apple", "adobe", "mozilla",
        "intel", "amd", "nvidia", "oracle", "vmware"
    ]

    p = publisher.lower()
    if any(t in p for t in trusted):
        return "Low"

    suspicious = ["crack", "keygen", "patch", "hack", "warez"]
    if any(s in p for s in suspicious):
        return "High"

    return "Medium"
