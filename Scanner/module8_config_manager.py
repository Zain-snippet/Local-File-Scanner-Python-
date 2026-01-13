# module8_config_manager.py

import os
import json
import tempfile


# --------------------------------------------------
# Defaults
# --------------------------------------------------


def get_default_config():
    return {
        
        "excluded_paths": [],

        "scan_paths": [
              "C:\\Users\\jahan\\Desktop\\Scanner (1)\\Scanner\\Test FIles"
        ],

        "vulnerability_db_path": "C:\\Users\\jahan\\Downloads\\Scanner\\vulnerabilities.json",

    }


# --------------------------------------------------
# Load / Save
# --------------------------------------------------

def load_config(filepath):
    default_cfg = get_default_config()
    
    
    if not isinstance(filepath, str) or not os.path.exists(filepath):
        return default_cfg

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        if not isinstance(user_cfg, dict):
            return default_cfg
    except Exception:
        return default_cfg

    final_cfg, _ = validate_config(user_cfg)
    return final_cfg

# --------------------------------------------------
# Accessors
# --------------------------------------------------

def get_scan_paths(config):
    if not isinstance(config, dict):
        return []
    paths = config.get("scan_paths", [])
    return [p for p in paths if isinstance(p, str) and p.strip()]


def get_excluded_paths(config):
    if not isinstance(config, dict):
        return []
    paths = config.get("excluded_paths", [])
    return [p for p in paths if isinstance(p, str) and p.strip()]


# --------------------------------------------------
# Validation
# --------------------------------------------------

def validate_config(config_dict):
    warnings = []
    defaults = get_default_config()
    cfg = {}
    
   
    vdb = config_dict.get("vulnerability_db_path")
    if isinstance(vdb, str) and vdb.strip():
        cfg["vulnerability_db_path"] = vdb
    else:
        cfg["vulnerability_db_path"] = defaults["vulnerability_db_path"]
        warnings.append("Invalid vulnerability_db_path")


    if not isinstance(config_dict, dict):
        warnings.append("Config not a dict. Reset to defaults.")
        return defaults, warnings

    # scan_paths
    sp = config_dict.get("scan_paths")
    if isinstance(sp, list) and all(isinstance(p, str) for p in sp):
        cfg["scan_paths"] = sp
    else:
        cfg["scan_paths"] = defaults["scan_paths"]
        warnings.append("Invalid scan_paths")

    # excluded_paths
    ep = config_dict.get("excluded_paths")
    if isinstance(ep, list) and all(isinstance(p, str) for p in ep):
        cfg["excluded_paths"] = ep
    else:
        cfg["excluded_paths"] = defaults["excluded_paths"]
        warnings.append("Invalid excluded_paths")

    # booleans
    for k in ("scan_executables", "scan_scripts", "scan_software", "save_reports", "fail_fast"):
        v = config_dict.get(k)
        cfg[k] = v if isinstance(v, bool) else defaults[k]
        if not isinstance(v, bool):
            warnings.append(f"Invalid {k}")

    # max_file_size_mb
    try:
        size = int(config_dict.get("max_file_size_mb"))
        if size <= 0:
            raise ValueError
        cfg["max_file_size_mb"] = size
    except Exception:
        cfg["max_file_size_mb"] = defaults["max_file_size_mb"]
        warnings.append("Invalid max_file_size_mb")

    # concurrency
    try:
        c = int(config_dict.get("concurrency"))
        if c < 1:
            raise ValueError
        cfg["concurrency"] = c
    except Exception:
        cfg["concurrency"] = defaults["concurrency"]
        warnings.append("Invalid concurrency")

    # report_format
    fmt = config_dict.get("report_format")
    if fmt in ("text", "json", "html"):
        cfg["report_format"] = fmt
    else:
        cfg["report_format"] = defaults["report_format"]
        warnings.append("Invalid report_format")

    return cfg, warnings

